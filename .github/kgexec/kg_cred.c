#include <linux/kg_cred.h>
#include <linux/kg_execmem.h>

#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pid_namespace.h>
#include <linux/hash.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#define KG_CRED_BITS	13
#define KG_CRED_SLOTS	(1 << KG_CRED_BITS)
#define KG_CRED_MAX	32768
#define KG_TRUST_MAX	512
#define KG_CMD_MAX	64
#define KG_LAST_MAX	112
#define KG_USER_OFF	100000
#define KG_APP_MIN	10000
#define KG_APP_MAX	19999
#define KG_SYS_MAX	9999
#define KG_SYS_UID	1000

#define KG_WHY_UID	1
#define KG_WHY_CAPS	2
#define KG_WHY_ROOT	3
#define KG_WHY_MODULE	4
#define KG_WHY_EXEC	5
#define KG_WHY_SUBJ	6

#define KG_BASE_SET	0
#define KG_BASE_KEEP	1
#define KG_BASE_ADOPT	2

DEFINE_STATIC_KEY_FALSE(kg_cred_key);

struct kg_ids {
	uid_t uid;
	uid_t euid;
	uid_t fsuid;
	uid_t gid;
	uid_t egid;
	uid_t fsgid;
	kernel_cap_t eff;
	kernel_cap_t perm;
	kernel_cap_t bset;
	kernel_cap_t amb;
};

struct kg_cred_rec {
	struct hlist_node node;
	struct rcu_head rcu;
	pid_t pid;
	u64 start;
	uid_t base;
	struct kg_ids ids;
};

static DEFINE_SPINLOCK(kg_ss_lock);
static pid_t kg_ss_tgid;
static u64 kg_ss_start;

static struct hlist_head kg_cred_tab[KG_CRED_SLOTS];
static DEFINE_SPINLOCK(kg_cred_lock);
static atomic_t kg_cred_recs = ATOMIC_INIT(0);
static atomic_t kg_cred_hits = ATOMIC_INIT(0);
static atomic_t kg_cred_notes = ATOMIC_INIT(0);
static atomic_t kg_cred_kills = ATOMIC_INIT(0);
static bool kg_cred_enforce;
static bool kg_cred_full;
static bool kg_cred_sealed;
static u8 kg_root_mode;
static u8 kg_mod_mode;
static u8 kg_exec_mode;
static char kg_cred_last[KG_LAST_MAX];
static DEFINE_SPINLOCK(kg_cred_last_lock);

static u32 kg_trust[KG_TRUST_MAX];
static int kg_trust_n;

static const char * const kg_exec_dirs[] = {
	"/system/",
	"/system_ext/",
	"/product/",
	"/vendor/",
	"/odm/",
	"/apex/",
	"/bin/",
	"/sbin/",
};

static bool kg_caps_empty(kernel_cap_t c)
{
	kernel_cap_t zero;

	memset(&zero, 0, sizeof(zero));

	return memcmp(&c, &zero, sizeof(c)) == 0;
}

static void kg_ids_of(struct kg_ids *d, const struct cred *c)
{
	d->uid = from_kuid(&init_user_ns, c->uid);
	d->euid = from_kuid(&init_user_ns, c->euid);
	d->fsuid = from_kuid(&init_user_ns, c->fsuid);
	d->gid = from_kgid(&init_user_ns, c->gid);
	d->egid = from_kgid(&init_user_ns, c->egid);
	d->fsgid = from_kgid(&init_user_ns, c->fsgid);
	d->eff = c->cap_effective;
	d->perm = c->cap_permitted;
	d->bset = c->cap_bset;
	d->amb = c->cap_ambient;
}

static const char *kg_ids_diff(const struct kg_ids *a, const struct kg_ids *b)
{
	if (a->uid != b->uid)
		return "uid";
	if (a->euid != b->euid)
		return "euid";
	if (a->fsuid != b->fsuid)
		return "fsuid";
	if (a->gid != b->gid)
		return "gid";
	if (a->egid != b->egid)
		return "egid";
	if (a->fsgid != b->fsgid)
		return "fsgid";
	if (memcmp(&a->eff, &b->eff, sizeof(a->eff)))
		return "cap_effective";
	if (memcmp(&a->perm, &b->perm, sizeof(a->perm)))
		return "cap_permitted";
	if (memcmp(&a->bset, &b->bset, sizeof(a->bset)))
		return "cap_bset";
	if (memcmp(&a->amb, &b->amb, sizeof(a->amb)))
		return "cap_ambient";

	return NULL;
}

static bool kg_exec_system_path(const char *path)
{
	size_t i;

	if (!path || *path != '/')
		return false;

	for (i = 0; i < ARRAY_SIZE(kg_exec_dirs); i++) {
		if (!strncmp(path, kg_exec_dirs[i], strlen(kg_exec_dirs[i])))
			return true;
	}

	return false;
}

static inline u32 kg_cred_slot(pid_t pid)
{
	return hash_32((u32)pid, KG_CRED_BITS);
}

static bool kg_trusted(u32 appid)
{
	int i, n = READ_ONCE(kg_trust_n);

	if (n > KG_TRUST_MAX)
		n = KG_TRUST_MAX;

	for (i = 0; i < n; i++) {
		if (READ_ONCE(kg_trust[i]) == appid)
			return true;
	}

	return false;
}

static struct kg_cred_rec *kg_cred_find(pid_t pid, u64 start)
{
	struct kg_cred_rec *r;

	hlist_for_each_entry_rcu(r, &kg_cred_tab[kg_cred_slot(pid)], node) {
		if (r->pid == pid && r->start == start)
			return r;
	}

	return NULL;
}

static void kg_cred_free(struct rcu_head *head)
{
	kfree(container_of(head, struct kg_cred_rec, rcu));
}

static void kg_cred_drop_locked(pid_t pid, u64 start)
{
	struct kg_cred_rec *r;

	hlist_for_each_entry(r, &kg_cred_tab[kg_cred_slot(pid)], node) {
		if (r->pid != pid)
			continue;
		if (start && r->start != start)
			continue;
		hlist_del_rcu(&r->node);
		atomic_dec(&kg_cred_recs);
		call_rcu(&r->rcu, kg_cred_free);
		return;
	}
}

static void kg_cred_sweep_locked(pid_t pid)
{
	struct hlist_node *tmp;
	struct kg_cred_rec *r;
	struct task_struct *t;

	hlist_for_each_entry_safe(r, tmp, &kg_cred_tab[kg_cred_slot(pid)], node) {
		rcu_read_lock();
		t = find_task_by_pid_ns(r->pid, &init_pid_ns);
		if (t && t->start_time == r->start) {
			rcu_read_unlock();
			continue;
		}
		rcu_read_unlock();
		hlist_del_rcu(&r->node);
		atomic_dec(&kg_cred_recs);
		call_rcu(&r->rcu, kg_cred_free);
	}
}

static void kg_cred_store(struct task_struct *task, const struct kg_ids *ids,
			  u8 base_mode)
{
	struct kg_cred_rec *r, *fresh;
	unsigned long flags;
	pid_t pid;
	u64 start;

	if (!task)
		return;

	pid = task_pid_nr(task);
	start = task->start_time;

	spin_lock_irqsave(&kg_cred_lock, flags);

	rcu_read_lock();
	r = kg_cred_find(pid, start);
	if (r) {
		r->ids = *ids;
		if (base_mode == KG_BASE_SET)
			WRITE_ONCE(r->base, ids->uid);
		else if (base_mode == KG_BASE_ADOPT &&
			 READ_ONCE(r->base) == 0 && ids->uid != 0)
			WRITE_ONCE(r->base, ids->uid);
		rcu_read_unlock();
		spin_unlock_irqrestore(&kg_cred_lock, flags);
		return;
	}
	rcu_read_unlock();

	kg_cred_sweep_locked(pid);
	kg_cred_drop_locked(pid, 0);

	if (atomic_read(&kg_cred_recs) >= KG_CRED_MAX) {
		if (!READ_ONCE(kg_cred_full)) {
			WRITE_ONCE(kg_cred_full, true);
			pr_warn("kg_cred: shadow table full at %d records, new tasks are not accounted\n",
				KG_CRED_MAX);
		}
		spin_unlock_irqrestore(&kg_cred_lock, flags);
		return;
	}

	fresh = kmalloc(sizeof(*fresh), GFP_ATOMIC);
	if (!fresh) {
		spin_unlock_irqrestore(&kg_cred_lock, flags);
		return;
	}

	fresh->pid = pid;
	fresh->start = start;
	fresh->base = ids->uid;
	fresh->ids = *ids;
	hlist_add_head_rcu(&fresh->node, &kg_cred_tab[kg_cred_slot(pid)]);
	atomic_inc(&kg_cred_recs);

	spin_unlock_irqrestore(&kg_cred_lock, flags);
}

static bool kg_cred_may_be_sysserver(const struct cred *c)
{
	if (!c)
		return false;
	if (from_kuid(&init_user_ns, c->uid) != KG_SYS_UID)
		return false;

	return !kg_caps_empty(c->cap_permitted);
}

static bool kg_task_is_sysserver(struct task_struct *t, const struct cred *c)
{
	struct task_struct *p, *gp;
	uid_t puid = (uid_t)-1;
	pid_t ppid = 0, gppid = 0;

	if (!t || !kg_cred_may_be_sysserver(c))
		return false;

	rcu_read_lock();
	p = rcu_dereference(t->real_parent);
	if (p) {
		const struct cred *pc = __task_cred(p);

		ppid = task_pid_nr(p);
		if (pc)
			puid = from_kuid(&init_user_ns, pc->uid);
		gp = rcu_dereference(p->real_parent);
		if (gp)
			gppid = task_pid_nr(gp);
	}
	rcu_read_unlock();

	return ppid > 1 && puid == 0 && gppid == 1;
}

static int kg_sysserver_pid(void)
{
	return READ_ONCE(kg_ss_tgid);
}

static bool kg_mark_sysserver(struct task_struct *t, bool force)
{
	struct task_struct *lead;
	unsigned long flags;
	pid_t tgid;
	u64 start;
	int held;

	lead = t->group_leader ? t->group_leader : t;
	tgid = task_tgid_nr(t);
	start = lead->start_time;

	spin_lock_irqsave(&kg_ss_lock, flags);
	held = kg_ss_tgid;
	if (held && held != tgid && !force) {
		spin_unlock_irqrestore(&kg_ss_lock, flags);
		pr_warn_ratelimited("kg_cred: pid %d comm %s denied system_server mark, pid %d holds it\n",
				    tgid, t->comm, held);
		return false;
	}
	WRITE_ONCE(kg_ss_tgid, tgid);
	WRITE_ONCE(kg_ss_start, start);
	spin_unlock_irqrestore(&kg_ss_lock, flags);

	if (held != tgid) {
		if (held)
			pr_info("kg_cred: system_server mark moved from pid %d\n",
				held);
		pr_info("kg_cred: pid %d comm %s marked as system_server\n",
			tgid, t->comm);
	}

	return true;
}

static void kg_sysserver_gone(struct task_struct *task)
{
	unsigned long flags;

	if (task_tgid_nr(task) != READ_ONCE(kg_ss_tgid))
		return;
	if (task->group_leader && task->group_leader != task)
		return;

	spin_lock_irqsave(&kg_ss_lock, flags);
	if (kg_ss_tgid == task_tgid_nr(task)) {
		WRITE_ONCE(kg_ss_tgid, 0);
		WRITE_ONCE(kg_ss_start, 0);
	}
	spin_unlock_irqrestore(&kg_ss_lock, flags);
}

static void kg_cred_note(u8 why, uid_t was, uid_t now, const char *what)
{
	static const char * const names[] = {
		"", "uid", "caps", "root", "module", "exec", "subj",
	};
	unsigned long flags;

	spin_lock_irqsave(&kg_cred_last_lock, flags);
	if (what)
		snprintf(kg_cred_last, sizeof(kg_cred_last),
			 "%s pid %d comm %s uid %u %s", names[why],
			 task_pid_nr(current), current->comm, was, what);
	else
		snprintf(kg_cred_last, sizeof(kg_cred_last),
			 "%s pid %d comm %s uid %u -> %u", names[why],
			 task_pid_nr(current), current->comm, was, now);
	spin_unlock_irqrestore(&kg_cred_last_lock, flags);
}

static bool kg_cred_react(u8 why, uid_t was, uid_t now, const char *what,
			  bool enforce)
{
	if (why == KG_WHY_MODULE || why == KG_WHY_EXEC || why == KG_WHY_SUBJ)
		atomic_inc(&kg_cred_notes);
	else
		atomic_inc(&kg_cred_hits);
	kg_cred_note(why, was, now, what);

	if (!enforce)
		return false;

	atomic_inc(&kg_cred_kills);
	force_sig(SIGKILL);

	return true;
}

void kg_cred_fork(struct task_struct *p)
{
	const struct cred *cred;
	struct kg_ids ids;

	if (!static_branch_unlikely(&kg_cred_key) || !p)
		return;

	rcu_read_lock();
	cred = __task_cred(p);
	if (!cred) {
		rcu_read_unlock();
		return;
	}
	kg_ids_of(&ids, cred);
	rcu_read_unlock();

	kg_cred_store(p, &ids, KG_BASE_SET);
}

void kg_cred_commit(struct task_struct *task, const struct cred *new)
{
	struct kg_cred_rec *r;
	struct kg_ids ids;
	uid_t newuid, base;
	bool root_now;
	u8 mode = READ_ONCE(kg_root_mode);

	if (!static_branch_unlikely(&kg_cred_key) || !task || !new)
		return;

	newuid = from_kuid(&init_user_ns, new->uid);

	rcu_read_lock();
	r = kg_cred_find(task_pid_nr(task), task->start_time);
	if (r)
		base = READ_ONCE(r->base);
	else
		base = from_kuid(&init_user_ns, __task_cred(task)->uid);
	rcu_read_unlock();

	root_now = newuid == 0 ||
		   from_kuid(&init_user_ns, new->euid) == 0 ||
		   from_kuid(&init_user_ns, new->fsuid) == 0;

	if (mode && root_now && base != 0 &&
	    !kg_trusted(base % KG_USER_OFF)) {
		pr_warn_ratelimited("kg_cred: pid %d comm %s uid %u asked for root\n",
				    task_pid_nr(task), task->comm, base);
		kg_cred_react(KG_WHY_ROOT, base, 0, NULL,
			      mode >= 2 && READ_ONCE(kg_cred_enforce) &&
			      task == current);
	}

	kg_ids_of(&ids, new);
	kg_cred_store(task, &ids, KG_BASE_ADOPT);
}

bool kg_cred_active(void)
{
	return static_branch_unlikely(&kg_cred_key) ? true : false;
}

bool kg_cred_is_system_server(void)
{
	struct task_struct *lead;
	pid_t held = READ_ONCE(kg_ss_tgid);

	if (!static_branch_unlikely(&kg_cred_key) || !held)
		return false;

	if (task_tgid_nr(current) != held)
		return false;

	lead = current->group_leader ? current->group_leader : current;

	return lead->start_time == READ_ONCE(kg_ss_start);
}

void kg_cred_exit(struct task_struct *task)
{
	unsigned long flags;

	if (!static_branch_unlikely(&kg_cred_key) || !task)
		return;

	kg_sysserver_gone(task);

	spin_lock_irqsave(&kg_cred_lock, flags);
	kg_cred_drop_locked(task_pid_nr(task), task->start_time);
	spin_unlock_irqrestore(&kg_cred_lock, flags);
}

static bool kg_cred_snapshot(struct kg_ids *now, struct kg_ids *want,
			     bool *mark_now)
{
	const struct cred *cur;
	struct kg_cred_rec *r;
	bool found;

	rcu_read_lock();
	cur = current_real_cred();
	kg_ids_of(now, cur);
	r = kg_cred_find(task_pid_nr(current), current->start_time);
	found = r != NULL;
	if (found) {
		*want = r->ids;
		if (mark_now && now->uid == KG_SYS_UID &&
		    !READ_ONCE(kg_ss_tgid))
			*mark_now = kg_task_is_sysserver(current, cur);
	}
	rcu_read_unlock();

	return found;
}

static void kg_cred_subj_check(void)
{
	const struct cred *subj, *real;
	struct kg_ids a, b;
	const char *what;

	if (current->flags & (PF_KTHREAD | PF_IO_WORKER))
		return;

	rcu_read_lock();
	subj = current_cred();
	real = current_real_cred();
	if (subj == real) {
		rcu_read_unlock();
		return;
	}
	kg_ids_of(&a, subj);
	kg_ids_of(&b, real);
	rcu_read_unlock();

	what = kg_ids_diff(&a, &b);
	if (!what)
		return;

	pr_warn_ratelimited("kg_cred: pid %d comm %s subjective cred differs in %s (uid %u vs %u)\n",
			    task_pid_nr(current), current->comm, what,
			    a.uid, b.uid);
	kg_cred_react(KG_WHY_SUBJ, b.uid, a.uid, what, false);
}

void kg_cred_check(void)
{
	struct kg_ids now, want;
	const char *what;
	bool mark_now = false;

	if (!static_branch_unlikely(&kg_cred_key))
		return;

	kg_cred_subj_check();

	if (!kg_cred_snapshot(&now, &want, &mark_now))
		return;

	if (mark_now)
		kg_mark_sysserver(current, false);

	what = kg_ids_diff(&now, &want);
	if (!what)
		return;

	if (!kg_cred_snapshot(&now, &want, NULL))
		return;

	what = kg_ids_diff(&now, &want);
	if (!what)
		return;

	pr_warn_ratelimited("kg_cred: pid %d comm %s %s changed without commit_creds (uid %u -> %u)\n",
			    task_pid_nr(current), current->comm, what,
			    want.uid, now.uid);
	kg_cred_react(now.uid != want.uid ? KG_WHY_UID : KG_WHY_CAPS,
		      want.uid, now.uid, now.uid != want.uid ? NULL : what,
		      READ_ONCE(kg_cred_enforce));
}

static bool kg_parent_is_kthread(void)
{
	struct task_struct *p;
	bool kt = false;

	rcu_read_lock();
	p = rcu_dereference(current->real_parent);
	if (p && (p->flags & PF_KTHREAD))
		kt = true;
	rcu_read_unlock();

	return kt;
}

static bool kg_self_on_system(void)
{
	struct file *exe;
	char *buf, *path;
	bool ok = false;

	if (!current->mm)
		return false;

	exe = get_mm_exe_file(current->mm);
	if (!exe)
		return false;

	buf = __getname();
	if (buf) {
		path = d_path(&exe->f_path, buf, PATH_MAX);
		if (!IS_ERR(path))
			ok = kg_exec_system_path(path);
		__putname(buf);
	}
	fput(exe);

	return ok;
}

bool kg_cred_block_module(void)
{
	uid_t uid;
	u8 mode = READ_ONCE(kg_mod_mode);

	if (!static_branch_unlikely(&kg_cred_key) || !mode)
		return false;

	if (!has_capability_noaudit(current, CAP_SYS_MODULE))
		return false;

	if (task_pid_nr(current) == 1)
		return false;

	if (kg_parent_is_kthread() && kg_self_on_system())
		return false;

	rcu_read_lock();
	uid = from_kuid(&init_user_ns, current_real_cred()->uid);
	rcu_read_unlock();

	pr_warn_ratelimited("kg_cred: pid %d comm %s uid %u tried to load a kernel module\n",
			    task_pid_nr(current), current->comm, uid);
	kg_cred_react(KG_WHY_MODULE, uid, uid, "kernel module", false);

	return mode >= 2;
}

bool kg_cred_block_exec(struct file *file)
{
	char *buf, *path = NULL;
	uid_t uid;
	u8 mode = READ_ONCE(kg_exec_mode);
	bool allow;

	if (!static_branch_unlikely(&kg_cred_key) || !mode || !file)
		return false;

	rcu_read_lock();
	uid = from_kuid(&init_user_ns, current_real_cred()->uid);
	rcu_read_unlock();

	if (uid == 0 || uid > KG_SYS_MAX)
		return false;

	buf = __getname();
	if (!buf)
		return mode >= 2;

	path = d_path(&file->f_path, buf, PATH_MAX);
	if (IS_ERR(path)) {
		__putname(buf);
		pr_warn_ratelimited("kg_cred: pid %d comm %s uid %u exec with unresolvable path\n",
				    task_pid_nr(current), current->comm, uid);
		return mode >= 2;
	}

	allow = kg_exec_system_path(path);
	if (!allow) {
		pr_warn_ratelimited("kg_cred: pid %d comm %s uid %u exec %s\n",
				    task_pid_nr(current), current->comm, uid,
				    path);
		kg_cred_react(KG_WHY_EXEC, uid, uid, path, false);
	}
	__putname(buf);

	return !allow && mode >= 2;
}

static void kg_cred_seed(void)
{
	struct task_struct *g, *t;
	const struct cred *cred;
	struct kg_ids ids;

	rcu_read_lock();
	for_each_process_thread(g, t) {
		cred = __task_cred(t);
		if (!cred)
			continue;
		kg_ids_of(&ids, cred);
		kg_cred_store(t, &ids, KG_BASE_SET);
		if (kg_task_is_sysserver(t, cred))
			kg_mark_sysserver(t, false);
	}
	rcu_read_unlock();
}

static void kg_cred_flush(void)
{
	struct hlist_node *tmp;
	struct kg_cred_rec *r;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&kg_cred_lock, flags);
	for (i = 0; i < KG_CRED_SLOTS; i++) {
		hlist_for_each_entry_safe(r, tmp, &kg_cred_tab[i], node) {
			hlist_del_rcu(&r->node);
			call_rcu(&r->rcu, kg_cred_free);
		}
	}
	atomic_set(&kg_cred_recs, 0);
	spin_unlock_irqrestore(&kg_cred_lock, flags);
}

static int kg_trust_add(u32 appid)
{
	unsigned long flags;
	int n;

	if (appid < KG_SYS_UID || appid > 99999)
		return -ERANGE;

	spin_lock_irqsave(&kg_cred_lock, flags);
	n = kg_trust_n;
	if (n >= KG_TRUST_MAX) {
		spin_unlock_irqrestore(&kg_cred_lock, flags);
		return -ENOSPC;
	}
	if (!kg_trusted(appid)) {
		kg_trust[n] = appid;
		smp_store_release(&kg_trust_n, n + 1);
	}
	spin_unlock_irqrestore(&kg_cred_lock, flags);

	return 0;
}

static void kg_trust_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&kg_cred_lock, flags);
	WRITE_ONCE(kg_trust_n, 0);
	memset(kg_trust, 0, sizeof(kg_trust));
	spin_unlock_irqrestore(&kg_cred_lock, flags);
}

static int kg_cred_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	int i, n;

	seq_puts(m, "abi 4\n");
	seq_printf(m, "on %d\n",
		   static_key_enabled(&kg_cred_key.key) ? 1 : 0);
	seq_printf(m, "enforce %d\n", READ_ONCE(kg_cred_enforce) ? 1 : 0);
	seq_printf(m, "root %u\n", READ_ONCE(kg_root_mode));
	seq_printf(m, "full %d\n", READ_ONCE(kg_cred_full) ? 1 : 0);
	seq_printf(m, "sealed %d\n", READ_ONCE(kg_cred_sealed) ? 1 : 0);
	seq_printf(m, "cap %d\n", KG_CRED_MAX);
	seq_printf(m, "module %u\n", READ_ONCE(kg_mod_mode));
	seq_printf(m, "exec %u\n", READ_ONCE(kg_exec_mode));
	seq_printf(m, "tracked %d\n", atomic_read(&kg_cred_recs));
	seq_printf(m, "hits %d\n", atomic_read(&kg_cred_hits));
	seq_printf(m, "notes %d\n", atomic_read(&kg_cred_notes));
	seq_printf(m, "sysserver %d\n", kg_sysserver_pid());
	seq_printf(m, "ssmarks %d\n", kg_sysserver_pid() ? 1 : 0);
	seq_printf(m, "kills %d\n", atomic_read(&kg_cred_kills));

	n = READ_ONCE(kg_trust_n);
	if (n > KG_TRUST_MAX)
		n = KG_TRUST_MAX;
	seq_printf(m, "trusted %d\n", n);
	for (i = 0; i < n; i++)
		seq_printf(m, "trust %u\n", READ_ONCE(kg_trust[i]));


	spin_lock_irqsave(&kg_cred_last_lock, flags);
	if (kg_cred_last[0])
		seq_printf(m, "last %s\n", kg_cred_last);
	spin_unlock_irqrestore(&kg_cred_last_lock, flags);

	return 0;
}

static int kg_cred_open(struct inode *inode, struct file *file)
{
	return single_open(file, kg_cred_show, NULL);
}

static int kg_cred_mode(const char *arg, u8 *dst)
{
	if (!strcmp(arg, "off"))
		*dst = 0;
	else if (!strcmp(arg, "watch"))
		*dst = 1;
	else if (!strcmp(arg, "deny"))
		*dst = 2;
	else
		return -EINVAL;

	return 0;
}

static ssize_t kg_cred_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *pos)
{
	char cmd[KG_CMD_MAX];
	char arg[KG_CMD_MAX];
	char *p;
	u8 mode;
	u32 appid;
	int pn = 0;
	size_t n = len;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (n >= sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, buf, n))
		return -EFAULT;
	cmd[n] = '\0';
	p = strim(cmd);

	if (!strcmp(p, "on")) {
		if (!static_key_enabled(&kg_cred_key.key)) {
			static_branch_enable(&kg_cred_key);
			kg_cred_seed();
		}
	} else if (!strcmp(p, "off")) {
		if (READ_ONCE(kg_cred_sealed))
			return -EPERM;
		if (kg_execmem_sys_active()) {
			pr_warn("kg_cred: refusing to switch off while the W^X profile for system uids is on\n");
			return -EBUSY;
		}
		if (static_key_enabled(&kg_cred_key.key))
			static_branch_disable(&kg_cred_key);
		kg_cred_flush();
	} else if (!strcmp(p, "seal")) {
		WRITE_ONCE(kg_cred_sealed, true);
	} else if (!strcmp(p, "enforce 1")) {
		WRITE_ONCE(kg_cred_enforce, true);
	} else if (!strcmp(p, "enforce 0")) {
		if (READ_ONCE(kg_cred_sealed))
			return -EPERM;
		WRITE_ONCE(kg_cred_enforce, false);
	} else if (!strcmp(p, "root 1")) {
		WRITE_ONCE(kg_root_mode, 2);
	} else if (!strcmp(p, "root 0")) {
		if (READ_ONCE(kg_cred_sealed))
			return -EPERM;
		WRITE_ONCE(kg_root_mode, 0);
	} else if (sscanf(p, "root %15s%n", arg, &pn) == 1 && !p[pn]) {
		if (kg_cred_mode(arg, &mode))
			return -EINVAL;
		if (mode < READ_ONCE(kg_root_mode) && READ_ONCE(kg_cred_sealed))
			return -EPERM;
		WRITE_ONCE(kg_root_mode, mode);
	} else if (sscanf(p, "sysserver %u%n", &appid, &pn) == 1 && !p[pn]) {
		struct task_struct *g2, *t, *want = NULL;
		bool found = false, fit = false;

		rcu_read_lock();
		for_each_process_thread(g2, t) {
			if (task_pid_nr(t) != (pid_t)appid)
				continue;
			found = true;
			fit = kg_cred_may_be_sysserver(__task_cred(t));
			if (fit) {
				get_task_struct(t);
				want = t;
			}
			goto looked;
		}
looked:
		rcu_read_unlock();

		if (!found)
			return -ESRCH;
		if (!want) {
			pr_warn("kg_cred: pid %u lacks system uid or capabilities, mark refused\n",
				appid);
			return -EPERM;
		}
		if (!kg_mark_sysserver(want, true)) {
			put_task_struct(want);
			return -EAGAIN;
		}
		put_task_struct(want);
	} else if (!strcmp(p, "reseed")) {
		if (READ_ONCE(kg_cred_sealed))
			return -EPERM;
		kg_cred_flush();
		if (static_key_enabled(&kg_cred_key.key))
			kg_cred_seed();
	} else if (!strcmp(p, "trust clear")) {
		if (READ_ONCE(kg_cred_sealed))
			return -EPERM;
		kg_trust_clear();
	} else if (sscanf(p, "trust %u%n", &appid, &pn) == 1 && !p[pn]) {
		int ret;

		if (READ_ONCE(kg_cred_sealed))
			return -EPERM;
		ret = kg_trust_add(appid);
		if (ret)
			return ret;
	} else if (sscanf(p, "module %15s%n", arg, &pn) == 1 && !p[pn]) {
		if (kg_cred_mode(arg, &mode))
			return -EINVAL;
		if (mode < READ_ONCE(kg_mod_mode) && READ_ONCE(kg_cred_sealed))
			return -EPERM;
		WRITE_ONCE(kg_mod_mode, mode);
	} else if (sscanf(p, "exec %15s%n", arg, &pn) == 1 && !p[pn]) {
		if (kg_cred_mode(arg, &mode))
			return -EINVAL;
		if (mode < READ_ONCE(kg_exec_mode) && READ_ONCE(kg_cred_sealed))
			return -EPERM;
		WRITE_ONCE(kg_exec_mode, mode);
	} else {
		return -EINVAL;
	}

	return len;
}

static const struct proc_ops kg_cred_ops = {
	.proc_open	= kg_cred_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= kg_cred_write,
};

static int __init kg_cred_init(void)
{
	int i;

	for (i = 0; i < KG_CRED_SLOTS; i++)
		INIT_HLIST_HEAD(&kg_cred_tab[i]);

	proc_create("kg_cred", 0600, NULL, &kg_cred_ops);

	return 0;
}

late_initcall(kg_cred_init);
