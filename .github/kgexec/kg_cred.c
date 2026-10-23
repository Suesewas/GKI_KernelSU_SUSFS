#include <linux/kg_cred.h>

#include <linux/atomic.h>
#include <linux/cred.h>
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
#define KG_CMD_MAX	64
#define KG_LAST_MAX	96

DEFINE_STATIC_KEY_FALSE(kg_cred_key);

struct kg_cred_rec {
	struct hlist_node node;
	struct rcu_head rcu;
	pid_t pid;
	u64 start;
	uid_t uid;
};

static struct hlist_head kg_cred_tab[KG_CRED_SLOTS];
static DEFINE_SPINLOCK(kg_cred_lock);
static atomic_t kg_cred_recs = ATOMIC_INIT(0);
static atomic_t kg_cred_hits = ATOMIC_INIT(0);
static atomic_t kg_cred_kills = ATOMIC_INIT(0);
static bool kg_cred_enforce;
static char kg_cred_last[KG_LAST_MAX];
static DEFINE_SPINLOCK(kg_cred_last_lock);

static inline u32 kg_cred_slot(pid_t pid)
{
	return hash_32((u32)pid, KG_CRED_BITS);
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

static void kg_cred_set(struct task_struct *task, uid_t uid)
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
	hlist_add_head_rcu(&fresh->node, &kg_cred_tab[kg_cred_slot(pid)]);
	atomic_inc(&kg_cred_recs);

	spin_unlock_irqrestore(&kg_cred_lock, flags);
}

static void kg_cred_note(uid_t was, uid_t now)
{
	unsigned long flags;

	spin_lock_irqsave(&kg_cred_last_lock, flags);
	snprintf(kg_cred_last, sizeof(kg_cred_last),
		 "pid %d comm %s uid %u -> %u", task_pid_nr(current),
		 current->comm, was, now);
	spin_unlock_irqrestore(&kg_cred_last_lock, flags);
}

void kg_cred_fork(struct task_struct *p)
{
	const struct cred *cred;
	uid_t uid;

	if (!static_branch_unlikely(&kg_cred_key) || !p)
		return;

	rcu_read_lock();
	cred = __task_cred(p);
	uid = cred ? from_kuid(&init_user_ns, cred->uid) : 0;
	rcu_read_unlock();

	kg_cred_set(p, uid);
}

void kg_cred_commit(struct task_struct *task, const struct cred *new)
{
	if (!static_branch_unlikely(&kg_cred_key) || !task || !new)
		return;

	kg_cred_set(task, from_kuid(&init_user_ns, new->uid));
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
	struct kg_cred_rec *r;
	uid_t uid, want;
	bool found;

	if (!static_branch_unlikely(&kg_cred_key))
		return;

	rcu_read_lock();
	uid = from_kuid(&init_user_ns, current_real_cred()->uid);
	rcu_read_unlock();
	if (uid != 0)
		return;

	rcu_read_lock();
	r = kg_cred_find(task_pid_nr(current), current->start_time);
	found = r != NULL;
	want = found ? READ_ONCE(r->uid) : 0;
	rcu_read_unlock();

	if (!found || want == 0)
		return;

	atomic_inc(&kg_cred_hits);
	kg_cred_note(want, uid);
	pr_warn_ratelimited("kg_cred: pid %d comm %s uid %u became root without commit_creds\n",
			    task_pid_nr(current), current->comm, want);

	if (!READ_ONCE(kg_cred_enforce))
		return;

	atomic_inc(&kg_cred_kills);
	force_sig(SIGKILL);
}

static void kg_cred_seed(void)
{
	struct task_struct *g, *t;
	const struct cred *cred;
	uid_t uid;

	rcu_read_lock();
	for_each_process_thread(g, t) {
		cred = __task_cred(t);
		uid = cred ? from_kuid(&init_user_ns, cred->uid) : 0;
		kg_cred_set(t, uid);
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

static int kg_cred_show(struct seq_file *m, void *v)
{
	unsigned long flags;

	seq_puts(m, "abi 1\n");
	seq_printf(m, "on %d\n",
		   static_key_enabled(&kg_cred_key.key) ? 1 : 0);
	seq_printf(m, "enforce %d\n", READ_ONCE(kg_cred_enforce) ? 1 : 0);
	seq_printf(m, "tracked %d\n", atomic_read(&kg_cred_recs));
	seq_printf(m, "hits %d\n", atomic_read(&kg_cred_hits));
	seq_printf(m, "kills %d\n", atomic_read(&kg_cred_kills));

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

static ssize_t kg_cred_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *pos)
{
	char cmd[KG_CMD_MAX];
	char *arg;
	size_t n = len;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (n >= sizeof(cmd))
		n = sizeof(cmd) - 1;
	if (copy_from_user(cmd, buf, n))
		return -EFAULT;
	cmd[n] = '\0';
	arg = strim(cmd);

	if (!strcmp(arg, "on")) {
		if (!static_key_enabled(&kg_cred_key.key)) {
			static_branch_enable(&kg_cred_key);
			kg_cred_seed();
		}
	} else if (!strcmp(arg, "off")) {
		if (static_key_enabled(&kg_cred_key.key))
			static_branch_disable(&kg_cred_key);
		kg_cred_flush();
	} else if (!strcmp(arg, "enforce 1")) {
		WRITE_ONCE(kg_cred_enforce, true);
	} else if (!strcmp(arg, "enforce 0")) {
		WRITE_ONCE(kg_cred_enforce, false);
	} else if (!strcmp(arg, "reseed")) {
		kg_cred_flush();
		if (static_key_enabled(&kg_cred_key.key))
			kg_cred_seed();
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
