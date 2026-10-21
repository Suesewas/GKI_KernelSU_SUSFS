// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "kg_execmem: " fmt

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include <linux/kg_execmem.h>

#define KG_ABI		3
#define KG_MAX_APPS	512
#define KG_APP_MIN	10000
#define KG_APP_MAX	19999
#define KG_USER_OFF	100000
#define KG_FLAG_MEM	1
#define KG_FLAG_FILE	2
#define KG_FLAG_WATCH	4
#define KG_FLAG_ALL	(KG_FLAG_MEM | KG_FLAG_FILE | KG_FLAG_WATCH)
#define KG_CMD_MAX	64
#define KG_OUT_MAX	8192

struct kg_table {
	struct rcu_head rcu;
	int count;
	u32 id[KG_MAX_APPS];
	u8 flags[KG_MAX_APPS];
	u8 seen[KG_MAX_APPS];
};

DEFINE_STATIC_KEY_FALSE(kg_execmem_key);

static struct kg_table __rcu *kg_table;
static DEFINE_MUTEX(kg_lock);
static bool kg_sealed;

static const char * const kg_allow[] = {
	"/system/",
	"/system_ext/",
	"/system_dlkm/",
	"/product/",
	"/vendor/",
	"/vendor_dlkm/",
	"/odm/",
	"/apex/",
	"/data/app/",
	"/data/dalvik-cache/",
};

static u8 kg_flags_now(void)
{
	struct kg_table *t;
	u32 appid;
	u8 flags = 0;
	int i;

	appid = from_kuid(&init_user_ns, current_uid()) % KG_USER_OFF;
	if (appid < KG_APP_MIN || appid > KG_APP_MAX)
		return 0;

	rcu_read_lock();
	t = rcu_dereference(kg_table);
	if (t) {
		for (i = 0; i < t->count; i++) {
			if (t->id[i] == appid) {
				flags = t->flags[i];
				break;
			}
		}
	}
	rcu_read_unlock();

	return flags;
}

static void kg_mark_seen(void)
{
	struct kg_table *t;
	u32 appid;
	int i;

	appid = from_kuid(&init_user_ns, current_uid()) % KG_USER_OFF;

	rcu_read_lock();
	t = rcu_dereference(kg_table);
	if (t) {
		for (i = 0; i < t->count; i++) {
			if (t->id[i] == appid) {
				if (!READ_ONCE(t->seen[i]))
					WRITE_ONCE(t->seen[i], 1);
				break;
			}
		}
	}
	rcu_read_unlock();
}

static const char * const kg_jit_name[] = {
	"memfd:jit-cache",
	"memfd:jit-zygote-cache",
};

static bool kg_jit_file(struct file *file)
{
	struct inode *inode = file_inode(file);
	const char *name;
	size_t i;

	if (!inode || !inode->i_sb || inode->i_sb->s_magic != TMPFS_MAGIC)
		return false;
	if (!file->f_path.dentry)
		return false;

	name = (const char *)file->f_path.dentry->d_name.name;
	if (!name)
		return false;

	for (i = 0; i < ARRAY_SIZE(kg_jit_name); i++) {
		if (strncmp(name, kg_jit_name[i], strlen(kg_jit_name[i])) == 0)
			return true;
	}

	return false;
}

static bool kg_path_ok(struct file *file, u8 flags)
{
	char *buf, *p;
	bool ok = false;
	size_t i;

	if (!(flags & KG_FLAG_MEM) && kg_jit_file(file))
		return true;

	buf = (char *)__get_free_page(GFP_KERNEL);
	if (!buf)
		return false;

	p = d_path(&file->f_path, buf, PAGE_SIZE);
	if (IS_ERR(p)) {
		free_page((unsigned long)buf);
		return false;
	}

	for (i = 0; i < ARRAY_SIZE(kg_allow); i++) {
		if (strncmp(p, kg_allow[i], strlen(kg_allow[i])) == 0) {
			ok = true;
			break;
		}
	}

	if (!ok)
		pr_warn_ratelimited("uid %u comm %s exec map denied: %s\n",
				    from_kuid(&init_user_ns, current_uid()),
				    current->comm, p);

	free_page((unsigned long)buf);
	return ok;
}

bool kg_execmem_block_mmap(struct file *file, unsigned long prot)
{
	u8 flags;

	if (!(prot & PROT_EXEC))
		return false;

	flags = kg_flags_now();
	if (!flags)
		return false;

	if (!file) {
		if (!(flags & KG_FLAG_MEM)) {
			if (flags & KG_FLAG_WATCH) {
				kg_mark_seen();
				pr_info_ratelimited("uid %u comm %s anonymous exec map observed\n",
						    from_kuid(&init_user_ns, current_uid()),
						    current->comm);
			}
			return false;
		}
		pr_warn_ratelimited("uid %u comm %s anonymous exec map denied\n",
				    from_kuid(&init_user_ns, current_uid()),
				    current->comm);
		return true;
	}

	if (!(flags & KG_FLAG_FILE))
		return false;

	return !kg_path_ok(file, flags);
}

bool kg_execmem_block_mprotect(struct vm_area_struct *vma,
			       unsigned long newflags)
{
	u8 flags;

	if (!(newflags & VM_EXEC) || (vma->vm_flags & VM_EXEC))
		return false;

	flags = kg_flags_now();
	if (!flags)
		return false;

	if (!vma->vm_file) {
		if (!(flags & KG_FLAG_MEM)) {
			if (flags & KG_FLAG_WATCH) {
				kg_mark_seen();
				pr_info_ratelimited("uid %u comm %s anonymous exec remap observed\n",
						    from_kuid(&init_user_ns, current_uid()),
						    current->comm);
			}
			return false;
		}
		pr_warn_ratelimited("uid %u comm %s anonymous exec remap denied\n",
				    from_kuid(&init_user_ns, current_uid()),
				    current->comm);
		return true;
	}

	if (!(flags & KG_FLAG_FILE))
		return false;

	return !kg_path_ok(vma->vm_file, flags);
}

static struct kg_table *kg_clone(struct kg_table *old)
{
	struct kg_table *t;

	t = kmalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return NULL;

	if (old) {
		t->count = old->count;
		memcpy(t->id, old->id, sizeof(t->id));
		memcpy(t->flags, old->flags, sizeof(t->flags));
		memcpy(t->seen, old->seen, sizeof(t->seen));
	} else {
		t->count = 0;
		memset(t->seen, 0, sizeof(t->seen));
	}

	return t;
}

static void kg_publish(struct kg_table *t)
{
	struct kg_table *old;

	old = rcu_dereference_protected(kg_table, lockdep_is_held(&kg_lock));
	rcu_assign_pointer(kg_table, t);

	if (t && t->count > 0)
		static_branch_enable(&kg_execmem_key);
	else
		static_branch_disable(&kg_execmem_key);

	if (old)
		kfree_rcu(old, rcu);
}

static int kg_add(u32 appid, u32 flags)
{
	struct kg_table *old, *t;
	int i;

	if (appid < KG_APP_MIN || appid > KG_APP_MAX)
		return -ERANGE;
	if (flags == 0 || flags > KG_FLAG_ALL)
		return -EINVAL;

	mutex_lock(&kg_lock);
	if (kg_sealed) {
		mutex_unlock(&kg_lock);
		return -EPERM;
	}

	old = rcu_dereference_protected(kg_table, lockdep_is_held(&kg_lock));
	t = kg_clone(old);
	if (!t) {
		mutex_unlock(&kg_lock);
		return -ENOMEM;
	}

	for (i = 0; i < t->count; i++) {
		if (t->id[i] == appid) {
			t->flags[i] = (u8)flags;
			t->seen[i] = 0;
			kg_publish(t);
			mutex_unlock(&kg_lock);
			return 0;
		}
	}

	if (t->count >= KG_MAX_APPS) {
		kfree(t);
		mutex_unlock(&kg_lock);
		return -ENOSPC;
	}

	t->id[t->count] = appid;
	t->flags[t->count] = (u8)flags;
	t->seen[t->count] = 0;
	t->count++;
	kg_publish(t);
	mutex_unlock(&kg_lock);

	return 0;
}

static int kg_del(u32 appid)
{
	struct kg_table *old, *t;
	int i, j;

	mutex_lock(&kg_lock);
	if (kg_sealed) {
		mutex_unlock(&kg_lock);
		return -EPERM;
	}

	old = rcu_dereference_protected(kg_table, lockdep_is_held(&kg_lock));
	if (!old || old->count == 0) {
		mutex_unlock(&kg_lock);
		return -ENOENT;
	}

	t = kg_clone(old);
	if (!t) {
		mutex_unlock(&kg_lock);
		return -ENOMEM;
	}

	for (i = 0, j = 0; i < old->count; i++) {
		if (old->id[i] == appid)
			continue;
		t->id[j] = old->id[i];
		t->flags[j] = old->flags[i];
		t->seen[j] = old->seen[i];
		j++;
	}

	if (j == old->count) {
		kfree(t);
		mutex_unlock(&kg_lock);
		return -ENOENT;
	}

	t->count = j;
	kg_publish(t);
	mutex_unlock(&kg_lock);

	return 0;
}

static int kg_clear(void)
{
	struct kg_table *t;

	mutex_lock(&kg_lock);
	if (kg_sealed) {
		mutex_unlock(&kg_lock);
		return -EPERM;
	}

	t = kg_clone(NULL);
	if (!t) {
		mutex_unlock(&kg_lock);
		return -ENOMEM;
	}

	kg_publish(t);
	mutex_unlock(&kg_lock);

	return 0;
}

static int kg_seal(void)
{
	mutex_lock(&kg_lock);
	kg_sealed = true;
	mutex_unlock(&kg_lock);

	return 0;
}

static ssize_t kg_proc_read(struct file *file, char __user *ubuf,
			    size_t len, loff_t *off)
{
	struct kg_table *t;
	char *out;
	int n = 0, i;
	ssize_t ret;

	out = kmalloc(KG_OUT_MAX, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	mutex_lock(&kg_lock);
	t = rcu_dereference_protected(kg_table, lockdep_is_held(&kg_lock));
	n += scnprintf(out + n, KG_OUT_MAX - n, "abi %d\n", KG_ABI);
	n += scnprintf(out + n, KG_OUT_MAX - n, "sealed %d\n", kg_sealed ? 1 : 0);
	n += scnprintf(out + n, KG_OUT_MAX - n, "count %d\n", t ? t->count : 0);
	if (t) {
		for (i = 0; i < t->count && n < KG_OUT_MAX - 32; i++)
			n += scnprintf(out + n, KG_OUT_MAX - n, "%u %u %u\n",
				       t->id[i], t->flags[i],
				       READ_ONCE(t->seen[i]));
	}
	mutex_unlock(&kg_lock);

	ret = simple_read_from_buffer(ubuf, len, off, out, n);
	kfree(out);

	return ret;
}

static ssize_t kg_proc_write(struct file *file, const char __user *ubuf,
			     size_t len, loff_t *off)
{
	char cmd[KG_CMD_MAX];
	char verb[16];
	unsigned int appid = 0, flags = 0;
	int got, ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (len == 0 || len >= sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, ubuf, len))
		return -EFAULT;
	cmd[len] = '\0';

	got = sscanf(cmd, "%15s %u %u", verb, &appid, &flags);
	if (got < 1)
		return -EINVAL;

	if (strcmp(verb, "add") == 0 && got >= 2)
		ret = kg_add(appid, got >= 3 ? flags : KG_FLAG_MEM);
	else if (strcmp(verb, "del") == 0 && got >= 2)
		ret = kg_del(appid);
	else if (strcmp(verb, "clear") == 0)
		ret = kg_clear();
	else if (strcmp(verb, "seal") == 0)
		ret = kg_seal();
	else
		ret = -EINVAL;

	return ret ? ret : (ssize_t)len;
}

static const struct proc_ops kg_proc_ops = {
	.proc_read	= kg_proc_read,
	.proc_write	= kg_proc_write,
	.proc_lseek	= default_llseek,
};

static int __init kg_execmem_init(void)
{
	if (!proc_create("kg_execmem", 0600, NULL, &kg_proc_ops))
		pr_warn("proc entry not created\n");

	return 0;
}

late_initcall(kg_execmem_init);
