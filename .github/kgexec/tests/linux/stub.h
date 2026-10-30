#ifndef KG_STUB_H
#define KG_STUB_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#ifndef EPERM
#define EPERM 1
#define ENOENT 2
#define ENOMEM 12
#define EFAULT 14
#define EINVAL 22
#define ENOSPC 28
#define ERANGE 34
#endif
#include <stddef.h>

typedef uint32_t u32;
struct rcu_head { int x; };
struct filename { const char *name; };
struct user_namespace { int x; };
extern struct user_namespace init_user_ns;
typedef struct { u32 val; } kuid_t;

extern u32 kg_test_uid;
static inline kuid_t current_uid(void) { kuid_t k; k.val = kg_test_uid; return k; }
static inline u32 from_kuid(struct user_namespace *ns, kuid_t k) { (void)ns; return k.val; }

struct mm_struct;
struct task { const char *comm; struct mm_struct *mm; int flags; };
extern struct task kg_current;
#define current (&kg_current)

#define __rcu
#define __user
#define GFP_KERNEL 0
#define kmalloc(n, f) malloc(n)
#define kfree(p) free(p)
#define kfree_rcu(p, field) free(p)
#define rcu_read_lock() do { } while (0)
#define rcu_read_unlock() do { } while (0)
#define rcu_dereference(p) (p)
#define rcu_dereference_protected(p, c) (p)
#define rcu_assign_pointer(p, v) ((p) = (v))
#define lockdep_is_held(x) 1
#define DEFINE_MUTEX(x) int x
#define mutex_lock(x) do { } while (0)
#define mutex_unlock(x) do { } while (0)
#define DEFINE_STATIC_KEY_FALSE(x) int x
#define static_branch_enable(x) do { } while (0)
#define static_branch_disable(x) do { } while (0)
#define pr_fmt(f) f
#define pr_info_ratelimited(...) do { } while (0)
#define pr_warn(...) do { } while (0)
#define scnprintf snprintf
#define strscpy(d, s, n) do { strncpy((d), (s), (n) - 1); (d)[(n) - 1] = '\0'; } while (0)
#define capable(x) 1
#define CAP_SYS_ADMIN 0
#define copy_from_user(d, s, n) (memcpy((d), (s), (n)), 0)
#define simple_read_from_buffer(ub, l, off, b, n) (0)
#define proc_create(a, b, c, d) (void *)1
#define default_llseek 0
#define __init
#define BUILD_BUG_ON(c) do { } while (0)

#define late_initcall(f) int kg_unused_init(void) { return f(); }
#define IS_ERR(p) (0)
#define ERR_PTR(e) ((void *)0)
struct file;
struct proc_ops { void *proc_read; void *proc_write; int proc_lseek; };
extern struct filename *kg_last_out;
static inline struct filename *getname_kernel(const char *s) {
    struct filename *f = malloc(sizeof(*f));
    char *c = strdup(s);
    f->name = c;
    kg_last_out = f;
    return f;
}
#include "linux/remapstub.h"

#endif
