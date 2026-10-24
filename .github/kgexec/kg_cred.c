#include <linux/kg_cred.h>

#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/fs.h>
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

#define KG_CRED_BITS	10
#define KG_CRED_SLOTS	(1 << KG_CRED_BITS)
#define KG_CRED_MAX	8192
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

DEFINE_STATIC_KEY_FALSE(kg_cred_key);

struct kg_cred_rec {
	struct hlist_node node;
	struct rcu_head rcu;
	pid_t pid;
	u64 start;
	uid_t uid;
	uid_t base;
	bool sysserver;
	kernel_cap_t eff;
	kernel_cap_t perm;
};

static struct hlist_head kg_cred_tab[KG_CRED_SLOTS];
static DEFINE_SPINLOCK(kg_cred_lock);
static atomic_t kg_cred_recs = ATOMIC_INIT(0);
static atomic_t kg_cred_hits = ATOMIC_INIT(0);
static atomic_t kg_cred_notes = ATOMIC_INIT(0);
static atomic_t kg_cred_kills = ATOMIC_INIT(0);
static bool kg_cred_enforce;
static bool kg_cred_root;
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

static bool kg_parent_is_init(struct task_struct *task)
{
	struct task_struct *p;
	pid_t ppid = 0;

	if (!task)
		return false;

	rcu_read_lock();
	p = rcu_dereference(task->real_parent);
	if (p)
		ppid = task_pid_nr(p);
	rcu_read_unlock();

	return ppid == 1;
}

static uid_t kg_parent_uid(struct task_struct *task)
{
	struct task_struct *p;
	const struct cred *c;
	uid_t uid = (uid_t)-1;

	if (!task)
		return uid;

	rcu_read_lock();
	p = rcu_dereference(task->real_parent);
	if (p) {
		c = __task_cred(p);
		if (c)
			uid = from_kuid(&init_user_ns, c->uid);
	}
	rcu_read_unlock();

	return uid;
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

static void kg_cred_store(struct task_struct *task, uid_t uid,
			  kernel_cap_t eff, kernel_cap_t perm, bool keep_base)
{
	struct kg_cred_rec *r, *fresh;
	unsigned long flags;
	pid_t pid;
	u64 start;

	if (!task)
		return;

	pid = task_pid_nr(task);
	start = task->start_time;

	fresh = kmalloc(sizeof(*fresh), GFP_ATOMIC);
	if (!fresh)
		return;

	spin_lock_irqsave(&kg_cred_lock, flags);

	rcu_read_lock();
	r = kg_cred_find(pid, start);
	if (r) {
		WRITE_ONCE(r->uid, uid);
		r->eff = eff;
		r->perm = perm;
		if (!keep_base)
			WRITE_ONCE(r->base, uid);
		rcu_read_unlock();
		spin_unlock_irqrestore(&kg_cred_lock, flags);
		kfree(fresh);
		return;
	}
	rcu_read_unlock();

	if (atomic_read(&kg_cred_recs) >= KG_CRED_MAX) {
		spin_unlock_irqrestore(&kg_cred_lock, flags);
		kfree(fresh);
		return;
	}

	kg_cred_drop_locked(pid, 0);

	fresh->pid = pid;
	fresh->start = start;
	fresh->uid = uid;
	fresh->base = uid;
	fresh->sysserver = false;
	fresh->eff = eff;
	fresh->perm = perm;
	hlist_add_head_rcu(&fresh->node, &kg_cred_tab[kg_cred_slot(pid)]);
	atomic_inc(&kg_cred_recs);

	spin_unlock_irqrestore(&kg_cred_lock, flags);
}

static void kg_cred_note(u8 why, uid_t was, uid_t now, const char *what)
{
	static const char * const names[] = {
		"", "uid", "caps", "root", "module", "exec",
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
	if (why == KG_WHY_MODULE || why == KG_WHY_EXEC)
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
	uid_t uid;
	kernel_cap_t eff, perm;

	if (!static_branch_unlikely(&kg_cred_key) || !p)
		return;

	rcu_read_lock();
	cred = __task_cred(p);
	if (!cred) {
		rcu_read_unlock();
		return;
	}
	uid = from_kuid(&init_user_ns, cred->uid);
	eff = cred->cap_effective;
	perm = cred->cap_permitted;
	rcu_read_unlock();

	kg_cred_store(p, uid, eff, perm, false);
}

void kg_cred_commit(struct task_struct *task, const struct cred *new)
{
	struct kg_cred_rec *r;
	uid_t newuid, base;
	bool found, deny = false;

	if (!static_branch_unlikely(&kg_cred_key) || !task || !new)
		return;

	newuid = from_kuid(&init_user_ns, new->uid);

	rcu_read_lock();
	r = kg_cred_find(task_pid_nr(task), task->start_time);
	found = r != NULL;
	base = found ? READ_ONCE(r->base) : newuid;
	rcu_read_unlock();

	if (READ_ONCE(kg_cred_root) && found && newuid == 0 && base != 0 &&
	    !kg_trusted(base % KG_USER_OFF)) {
		pr_warn_ratelimited("kg_cred: pid %d comm %s uid %u asked for root\n",
				    task_pid_nr(task), task->comm, base);
		deny = kg_cred_react(KG_WHY_ROOT, base, 0, NULL,
				     READ_ONCE(kg_cred_enforce) &&
				     task == current);
	}

	if (deny)
		return;

	kg_cred_store(task, newuid, new->cap_effective, new->cap_permitted,
		      true);

	if (newuid == KG_SYS_UID && base == 0 &&
	    !kg_caps_empty(new->cap_permitted) &&
	    !kg_parent_is_init(task) && kg_parent_uid(task) == 0) {
		bool fresh = false;

		rcu_read_lock();
		r = kg_cred_find(task_pid_nr(task), task->start_time);
		if (r && !READ_ONCE(r->sysserver)) {
			WRITE_ONCE(r->sysserver, true);
			fresh = true;
		}
		rcu_read_unlock();

		if (fresh)
			pr_info("kg_cred: pid %d marked as system_server\n",
				task_pid_nr(task));
	}
}

bool kg_cred_active(void)
{
	return static_branch_unlikely(&kg_cred_key) ? true : false;
}

bool kg_cred_is_system_server(void)
{
	struct kg_cred_rec *r;
	bool mark = false;

	if (!static_branch_unlikely(&kg_cred_key))
		return false;

	rcu_read_lock();
	r = kg_cred_find(task_pid_nr(current), current->start_time);
	if (r)
		mark = READ_ONCE(r->sysserver);
	rcu_read_unlock();

	return mark;
}

void kg_cred_exit(struct task_struct *task)
{
	unsigned long flags;

	if (!static_branch_unlikely(&kg_cred_key) || !task)
		return;

	spin_lock_irqsave(&kg_cred_lock, flags);
	kg_cred_drop_locked(task_pid_nr(task), task->start_time);
	spin_unlock_irqrestore(&kg_cred_lock, flags);
}

void kg_cred_check(void)
{
	const struct cred *cur;
	struct kg_cred_rec *r;
	uid_t uid, want;
	kernel_cap_t eff, perm;
	bool found, caps_bad;

	if (!static_branch_unlikely(&kg_cred_key))
		return;

	rcu_read_lock();
	cur = current_real_cred();
	uid = from_kuid(&init_user_ns, cur->uid);
	eff = cur->cap_effective;
	perm = cur->cap_permitted;
	r = kg_cred_find(task_pid_nr(current), current->start_time);
	found = r != NULL;
	want = found ? READ_ONCE(r->uid) : uid;
	caps_bad = found &&
		   (memcmp(&eff, &r->eff, sizeof(eff)) != 0 ||
		    memcmp(&perm, &r->perm, sizeof(perm)) != 0);
	rcu_read_unlock();

	if (!found)
		return;

	if (uid != want) {
		pr_warn_ratelimited("kg_cred: pid %d comm %s uid %u -> %u without commit_creds\n",
				    task_pid_nr(current), current->comm, want,
				    uid);
		kg_cred_react(KG_WHY_UID, want, uid, NULL,
			      READ_ONCE(kg_cred_enforce));
		return;
	}

	if (caps_bad) {
		pr_warn_ratelimited("kg_cred: pid %d comm %s caps changed without commit_creds\n",
				    task_pid_nr(current), current->comm);
		kg_cred_react(KG_WHY_CAPS, uid, uid, "caps changed",
			      READ_ONCE(kg_cred_enforce));
	}
}

bool kg_cred_block_module(void)
{
	uid_t uid;
	u8 mode = READ_ONCE(kg_mod_mode);

	if (!static_branch_unlikely(&kg_cred_key) || !mode)
		return false;

	rcu_read_lock();
	uid = from_kuid(&init_user_ns, current_real_cred()->uid);
	rcu_read_unlock();

	if (uid == 0 && (!strcmp(current->comm, "init") ||
			 !strcmp(current->comm, "modprobe") ||
			 !strcmp(current->comm, "vendor_modprobe")))
		return false;

	pr_warn_ratelimited("kg_cred: pid %d comm %s uid %u tried to load a kernel module\n",
			    task_pid_nr(current), current->comm, uid);
	kg_cred_react(KG_WHY_MODULE, uid, uid, "kernel module", false);

	return mode >= 2;
}

bool kg_cred_block_exec(const char *path)
{
	uid_t uid;
	u8 mode = READ_ONCE(kg_exec_mode);

	if (!static_branch_unlikely(&kg_cred_key) || !mode)
		return false;

	rcu_read_lock();
	uid = from_kuid(&init_user_ns, current_real_cred()->uid);
	rcu_read_unlock();

	if (uid == 0 || uid > KG_SYS_MAX)
		return false;

	if (kg_parent_is_init(current))
		return false;

	if (kg_exec_system_path(path))
		return false;

	pr_warn_ratelimited("kg_cred: pid %d comm %s uid %u exec %s\n",
			    task_pid_nr(current), current->comm, uid,
			    path ? path : "?");
	kg_cred_react(KG_WHY_EXEC, uid, uid, path ? path : "exec", false);

	return mode >= 2;
}

static void kg_cred_seed(void)
{
	struct task_struct *g, *t;
	const struct cred *cred;
	uid_t uid;
	kernel_cap_t eff, perm;

	rcu_read_lock();
	for_each_process_thread(g, t) {
		cred = __task_cred(t);
		if (!cred)
			continue;
		uid = from_kuid(&init_user_ns, cred->uid);
		eff = cred->cap_effective;
		perm = cred->cap_permitted;
		kg_cred_store(t, uid, eff, perm, false);
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

	if (appid < KG_APP_MIN || appid > KG_APP_MAX)
		return -ERANGE;

	spin_lock_irqsave(&kg_cred_lock, flags);
	n = kg_trust_n;
	if (n >= KG_TRUST_MAX) {
		spin_unlock_irqrestore(&kg_cred_lock, flags);
		return -ENOSPC;
	}
	if (!kg_trusted(appid)) {
		kg_trust[n] = appid;
		WRITE_ONCE(kg_trust_n, n + 1);
	}
	spin_unlock_irqrestore(&kg_cred_lock, flags);

	return 0;
}

static void kg_trust_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&kg_cred_lock, flags);
	WRITE_ONCE(kg_trust_n, 0);
	spin_unlock_irqrestore(&kg_cred_lock, flags);
}

static int kg_cred_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	int i, n;

	seq_puts(m, "abi 3\n");
	seq_printf(m, "on %d\n",
		   static_key_enabled(&kg_cred_key.key) ? 1 : 0);
	seq_printf(m, "enforce %d\n", READ_ONCE(kg_cred_enforce) ? 1 : 0);
	seq_printf(m, "root %d\n", READ_ONCE(kg_cred_root) ? 1 : 0);
	seq_printf(m, "module %u\n", READ_ONCE(kg_mod_mode));
	seq_printf(m, "exec %u\n", READ_ONCE(kg_exec_mode));
	seq_printf(m, "tracked %d\n", atomic_read(&kg_cred_recs));
	seq_printf(m, "hits %d\n", atomic_read(&kg_cred_hits));
	seq_printf(m, "notes %d\n", atomic_read(&kg_cred_notes));
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
	size_t n = len;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (n >= sizeof(cmd))
		n = sizeof(cmd) - 1;
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
		if (static_key_enabled(&kg_cred_key.key))
			static_branch_disable(&kg_cred_key);
		kg_cred_flush();
	} else if (!strcmp(p, "enforce 1")) {
		WRITE_ONCE(kg_cred_enforce, true);
	} else if (!strcmp(p, "enforce 0")) {
		WRITE_ONCE(kg_cred_enforce, false);
	} else if (!strcmp(p, "root 1")) {
		WRITE_ONCE(kg_cred_root, true);
	} else if (!strcmp(p, "root 0")) {
		WRITE_ONCE(kg_cred_root, false);
	} else if (!strcmp(p, "reseed")) {
		kg_cred_flush();
		if (static_key_enabled(&kg_cred_key.key))
			kg_cred_seed();
	} else if (!strcmp(p, "trust clear")) {
		kg_trust_clear();
	} else if (sscanf(p, "trust %u", &appid) == 1) {
		int ret = kg_trust_add(appid);

		if (ret)
			return ret;
	} else if (sscanf(p, "module %15s", arg) == 1) {
		if (kg_cred_mode(arg, &mode))
			return -EINVAL;
		WRITE_ONCE(kg_mod_mode, mode);
	} else if (sscanf(p, "exec %15s", arg) == 1) {
		if (kg_cred_mode(arg, &mode))
			return -EINVAL;
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
