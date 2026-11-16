#ifndef KG_EXEC_STUB_H
#define KG_EXEC_STUB_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifndef EPERM
#define EPERM 1
#define ENOENT 2
#define EIO 5
#define ENOMEM 12
#define EFAULT 14
#define EINVAL 22
#define ENOSPC 28
#define ERANGE 34
#define ENOTSUPP 524
#define EBUSY 16
#endif

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef ssize_t kg_ssize_t;

struct rcu_head { int x; };
struct user_namespace { int x; };
extern struct user_namespace init_user_ns;
typedef struct { u32 val; } kuid_t;

extern u32 kg_test_uid;
static inline kuid_t current_uid(void) { kuid_t k; k.val = kg_test_uid; return k; }
static inline u32 from_kuid(struct user_namespace *ns, kuid_t k) { (void)ns; return k.val; }

struct task { const char *comm; };
extern struct task kg_current;
#define current (&kg_current)

/* -- отображение файла: путь, тип носителя, содержимое -- */
#define TMPFS_MAGIC 0x01021994
#define HUGETLBFS_MAGIC 0x958458f6
#define RAMFS_MAGIC 0x858458f6

struct super_block { unsigned long s_magic; };
struct inode { unsigned int i_mode; struct super_block *i_sb; long i_size; };
struct kg_dentry_name { const unsigned char *name; };
struct dentry { struct kg_dentry_name d_name; };
struct path { struct dentry *dentry; };
struct file {
	unsigned int f_mode;
	struct path f_path;
	struct inode *inode;
	struct super_block sb;
	struct dentry dent;
	const char *path;
	const char *body;
	long body_n;
	struct inode ino;
};

#define FMODE_READ 1
#define S_IFREG 0100000
#define S_ISREG(m) (((m) & 0170000) == S_IFREG)

static inline struct inode *file_inode(struct file *f) { return f ? f->inode : NULL; }
static inline long i_size_read(struct inode *i) { return i ? i->i_size : 0; }

#define PAGE_SIZE 4096

extern char *kg_d_path(struct file *f, char *buf, int n);
#define d_path(p, buf, n) kg_d_path_path((p), (buf), (n))
extern char *kg_d_path_path(struct path *p, char *buf, int n);

static inline unsigned long __get_free_page(int gfp) { (void)gfp; return (unsigned long)malloc(PAGE_SIZE); }
static inline void free_page(unsigned long p) { free((void *)p); }

extern long kg_kernel_read(struct file *f, void *buf, size_t n, loff_t *pos);
#define kernel_read(f, b, n, p) kg_kernel_read((f), (b), (n), (p))

/* -- мелочи ядра -- */
#define GFP_KERNEL 0
#define kmalloc(n, f) malloc(n)
#define kfree(p) free(p)
#define kfree_rcu(p, field) free(p)
#define kvmalloc(n, f) malloc(n)
#define kvfree(p) free(p)
#define __rcu
#define __user
#define __init
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
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define pr_fmt(f) f
#define pr_info_ratelimited(...) do { } while (0)
#define pr_warn_ratelimited(...) do { } while (0)
#define pr_warn(...) do { } while (0)
#define scnprintf snprintf
#define strscpy(d, s, n) do { strncpy((d), (s), (n) - 1); (d)[(n) - 1] = '\0'; } while (0)
#define capable(x) 1
#define CAP_SYS_ADMIN 0
#define copy_from_user(d, s, n) (memcpy((d), (s), (n)), 0)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define IS_ERR(p) (0)
#define PTR_ERR(p) (-EINVAL)
#define ERR_PTR(e) ((void *)0)

typedef struct { int v; } atomic_t;
#define ATOMIC_INIT(x) { x }
static inline int atomic_read(atomic_t *a) { return a->v; }
static inline void atomic_set(atomic_t *a, int v) { a->v = v; }
static inline int atomic_fetch_inc(atomic_t *a) { return a->v++; }
static inline void atomic_inc(atomic_t *a) { a->v++; }

static inline u32 get_unaligned_le32(const void *p)
{
	const unsigned char *b = p;

	return (u32)b[0] | ((u32)b[1] << 8) | ((u32)b[2] << 16) | ((u32)b[3] << 24);
}

static inline long kg_stub_read_buf(char *ub, unsigned long l, loff_t *off,
				    const char *b, long n)
{
	long pos = off ? (long)*off : 0;
	long take;

	if (pos >= n)
		return 0;
	take = n - pos;
	if ((unsigned long)take > l)
		take = (long)l;
	memcpy(ub, b + pos, (size_t)take);
	if (off)
		*off = pos + take;
	return take;
}
#define simple_read_from_buffer(ub, l, off, b, n) \
	kg_stub_read_buf((ub), (l), (off), (b), (n))
#define proc_create(a, b, c, d) (void *)1
#define default_llseek 0
#define late_initcall(f) int kg_unused_init(void) { return f(); }
struct proc_ops { void *proc_read; void *proc_write; int proc_lseek; };

/* -- слой прав: приложение не системное и не system_server -- */
extern int kg_cred_on;
extern u32 kg_cred_base;
static inline bool kg_cred_active(void) { return kg_cred_on != 0; }
static inline u32 kg_cred_base_appid(void) { return kg_cred_base; }
static inline bool kg_cred_is_system_server(void) { return false; }

/* -- отображения памяти -- */
#define PROT_EXEC 4
#define PROT_WRITE 2
#define VM_EXEC 4
#define VM_WRITE 2
struct vm_area_struct { unsigned long vm_flags; struct file *vm_file; };

static inline bool is_compat_task(void) { return false; }

#endif
