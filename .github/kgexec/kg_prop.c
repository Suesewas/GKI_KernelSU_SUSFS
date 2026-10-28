// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "kg_prop: " fmt

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include <linux/kg_prop.h>

#define KG_PROP_ABI	2
#define KG_PROP_MAX	192
#define KG_PROP_LEN	128
#define KG_APP_MIN	10000
#define KG_APP_MAX	19999
#define KG_USER_OFF	100000
#define KG_USER_MAX	999
#define KG_CMD_MAX	512
#define KG_OUT_MAX	8192

/*
 * key holds either a full uid (userid * KG_USER_OFF + appid), which matches
 * that one app in that one android user, or a bare appid (KG_APP_MIN..
 * KG_APP_MAX), which matches that app in every user. ABI 1 only ever wrote
 * bare appids, so ABI 1 commands keep their old meaning.
 */
struct kg_prop_entry {
	u32 key;
	u32 tlen;
	char target[KG_PROP_LEN];
	char redirect[KG_PROP_LEN];
};

struct kg_prop_table {
	struct rcu_head rcu;
	int count;
	struct kg_prop_entry e[KG_PROP_MAX];
};

DEFINE_STATIC_KEY_FALSE(kg_prop_key);

static struct kg_prop_table __rcu *kg_prop_map;
static DEFINE_MUTEX(kg_prop_lock);
static bool kg_prop_sealed;

struct filename *kg_prop_redirect(struct filename *name)
{
	struct kg_prop_table *t;
	struct filename *out;
	char buf[KG_PROP_LEN];
	const char *p;
	bool found = false;
	u32 uid, appid;
	size_t len;
	int i;

	if (!name || IS_ERR(name))
		return NULL;

	p = name->name;
	if (!p || p[0] != '/')
		return NULL;

	uid = from_kuid(&init_user_ns, current_uid());
	appid = uid % KG_USER_OFF;
	if (appid < KG_APP_MIN || appid > KG_APP_MAX)
		return NULL;

	len = strnlen(p, KG_PROP_LEN);
	if (len == 0 || len >= KG_PROP_LEN)
		return NULL;

	rcu_read_lock();
	t = rcu_dereference(kg_prop_map);
	if (t) {
		int exact = -1, wild = -1;

		for (i = 0; i < t->count; i++) {
			bool is_exact, is_wild;

			if (t->e[i].tlen != (u32)len)
				continue;
			is_exact = t->e[i].key == uid;
			is_wild = t->e[i].key == appid;
			if (!is_exact && !is_wild)
				continue;
			if (memcmp(t->e[i].target, p, len) != 0)
				continue;
			if (is_exact) {
				exact = i;
				break;
			}
			if (wild < 0)
				wild = i;
		}

		/* a per-user key always wins over an all-users appid key,
		 * whatever order they were added in
		 */
		i = exact >= 0 ? exact : wild;
		if (i >= 0) {
			memcpy(buf, t->e[i].redirect, KG_PROP_LEN);
			found = true;
		}
	}
	rcu_read_unlock();

	if (!found)
		return NULL;

	buf[KG_PROP_LEN - 1] = '\0';
	out = getname_kernel(buf);
	if (IS_ERR(out))
		return NULL;

	pr_info_ratelimited("uid %u comm %s redirect %s -> %s\n",
			    uid, current->comm, p, buf);

	return out;
}

static struct kg_prop_table *kg_prop_clone(struct kg_prop_table *old)
{
	struct kg_prop_table *t;

	t = kmalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return NULL;

	if (old) {
		t->count = old->count;
		memcpy(t->e, old->e, sizeof(t->e));
	} else {
		t->count = 0;
		memset(t->e, 0, sizeof(t->e));
	}

	return t;
}

static void kg_prop_publish(struct kg_prop_table *t)
{
	struct kg_prop_table *old;

	old = rcu_dereference_protected(kg_prop_map,
					lockdep_is_held(&kg_prop_lock));
	rcu_assign_pointer(kg_prop_map, t);

	if (t && t->count > 0)
		static_branch_enable(&kg_prop_key);
	else
		static_branch_disable(&kg_prop_key);

	if (old)
		kfree_rcu(old, rcu);
}

static bool kg_prop_path_ok(const char *p)
{
	size_t len;

	if (!p || p[0] != '/')
		return false;

	len = strnlen(p, KG_PROP_LEN);
	if (len == 0 || len >= KG_PROP_LEN)
		return false;

	if (strstr(p, "/../"))
		return false;

	return true;
}

static bool kg_prop_key_ok(u32 key)
{
	u32 appid = key % KG_USER_OFF;

	if (appid < KG_APP_MIN || appid > KG_APP_MAX)
		return false;
	if (key / KG_USER_OFF > KG_USER_MAX)
		return false;

	return true;
}

static int kg_prop_add(u32 key, const char *target, const char *redirect)
{
	struct kg_prop_table *old, *t;
	size_t tlen;
	int i;

	if (!kg_prop_key_ok(key))
		return -ERANGE;
	if (!kg_prop_path_ok(target) || !kg_prop_path_ok(redirect))
		return -EINVAL;

	tlen = strnlen(target, KG_PROP_LEN);

	mutex_lock(&kg_prop_lock);
	if (kg_prop_sealed) {
		mutex_unlock(&kg_prop_lock);
		return -EPERM;
	}

	old = rcu_dereference_protected(kg_prop_map,
					lockdep_is_held(&kg_prop_lock));
	t = kg_prop_clone(old);
	if (!t) {
		mutex_unlock(&kg_prop_lock);
		return -ENOMEM;
	}

	for (i = 0; i < t->count; i++) {
		if (t->e[i].key != key)
			continue;
		if (strncmp(t->e[i].target, target, KG_PROP_LEN) != 0)
			continue;
		strscpy(t->e[i].redirect, redirect, KG_PROP_LEN);
		kg_prop_publish(t);
		mutex_unlock(&kg_prop_lock);
		return 0;
	}

	if (t->count >= KG_PROP_MAX) {
		kfree(t);
		mutex_unlock(&kg_prop_lock);
		return -ENOSPC;
	}

	t->e[t->count].key = key;
	t->e[t->count].tlen = (u32)tlen;
	strscpy(t->e[t->count].target, target, KG_PROP_LEN);
	strscpy(t->e[t->count].redirect, redirect, KG_PROP_LEN);
	t->count++;
	kg_prop_publish(t);
	mutex_unlock(&kg_prop_lock);

	return 0;
}

static int kg_prop_del(u32 key)
{
	struct kg_prop_table *old, *t;
	int i, j;

	mutex_lock(&kg_prop_lock);
	if (kg_prop_sealed) {
		mutex_unlock(&kg_prop_lock);
		return -EPERM;
	}

	old = rcu_dereference_protected(kg_prop_map,
					lockdep_is_held(&kg_prop_lock));
	if (!old || old->count == 0) {
		mutex_unlock(&kg_prop_lock);
		return -ENOENT;
	}

	t = kg_prop_clone(old);
	if (!t) {
		mutex_unlock(&kg_prop_lock);
		return -ENOMEM;
	}

	for (i = 0, j = 0; i < old->count; i++) {
		if (old->e[i].key == key)
			continue;
		t->e[j] = old->e[i];
		j++;
	}

	if (j == old->count) {
		kfree(t);
		mutex_unlock(&kg_prop_lock);
		return -ENOENT;
	}

	t->count = j;
	kg_prop_publish(t);
	mutex_unlock(&kg_prop_lock);

	return 0;
}

static int kg_prop_clear(void)
{
	struct kg_prop_table *t;

	mutex_lock(&kg_prop_lock);
	if (kg_prop_sealed) {
		mutex_unlock(&kg_prop_lock);
		return -EPERM;
	}

	t = kg_prop_clone(NULL);
	if (!t) {
		mutex_unlock(&kg_prop_lock);
		return -ENOMEM;
	}

	kg_prop_publish(t);
	mutex_unlock(&kg_prop_lock);

	return 0;
}

static int kg_prop_seal(void)
{
	mutex_lock(&kg_prop_lock);
	kg_prop_sealed = true;
	mutex_unlock(&kg_prop_lock);

	return 0;
}

static ssize_t kg_prop_proc_read(struct file *file, char __user *ubuf,
				 size_t len, loff_t *off)
{
	struct kg_prop_table *t;
	char *out;
	int n = 0, i;
	ssize_t ret;

	out = kmalloc(KG_OUT_MAX, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	mutex_lock(&kg_prop_lock);
	t = rcu_dereference_protected(kg_prop_map,
				      lockdep_is_held(&kg_prop_lock));
	n += scnprintf(out + n, KG_OUT_MAX - n, "abi %d\n", KG_PROP_ABI);
	n += scnprintf(out + n, KG_OUT_MAX - n, "sealed %d\n",
		       kg_prop_sealed ? 1 : 0);
	n += scnprintf(out + n, KG_OUT_MAX - n, "count %d\n", t ? t->count : 0);
	if (t) {
		for (i = 0; i < t->count && n < KG_OUT_MAX - 2 * KG_PROP_LEN; i++)
			n += scnprintf(out + n, KG_OUT_MAX - n, "%u %s %s\n",
				       t->e[i].key, t->e[i].target,
				       t->e[i].redirect);
	}
	mutex_unlock(&kg_prop_lock);

	ret = simple_read_from_buffer(ubuf, len, off, out, n);
	kfree(out);

	return ret;
}

static ssize_t kg_prop_proc_write(struct file *file, const char __user *ubuf,
				  size_t len, loff_t *off)
{
	char cmd[KG_CMD_MAX];
	char verb[16];
	char target[KG_PROP_LEN];
	char redirect[KG_PROP_LEN];
	unsigned int key = 0;
	int got, ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (len == 0 || len >= sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, ubuf, len))
		return -EFAULT;
	cmd[len] = '\0';

	got = sscanf(cmd, "%15s %u %191s %191s", verb, &key, target, redirect);
	if (got < 1)
		return -EINVAL;

	if (strcmp(verb, "add") == 0 && got >= 4)
		ret = kg_prop_add(key, target, redirect);
	else if (strcmp(verb, "del") == 0 && got >= 2)
		ret = kg_prop_del(key);
	else if (strcmp(verb, "clear") == 0)
		ret = kg_prop_clear();
	else if (strcmp(verb, "seal") == 0)
		ret = kg_prop_seal();
	else
		ret = -EINVAL;

	return ret ? ret : (ssize_t)len;
}

static const struct proc_ops kg_prop_proc_ops = {
	.proc_read	= kg_prop_proc_read,
	.proc_write	= kg_prop_proc_write,
	.proc_lseek	= default_llseek,
};

static int __init kg_prop_init(void)
{
	if (!proc_create("kg_prop", 0600, NULL, &kg_prop_proc_ops))
		pr_warn("proc entry not created\n");

	return 0;
}

late_initcall(kg_prop_init);
