#ifndef KG_REMAP_STUB_H
#define KG_REMAP_STUB_H
/* подмена унаследованного отображения: фальшивые mm, vma и vm_mmap */
#define GFP_ATOMIC 0
#define kcalloc(n, sz, f) calloc((n), (sz))
#define PF_KTHREAD 0x00200000
#define O_RDONLY 0
#define O_CLOEXEC 0
#define PROT_READ 1
#define MAP_PRIVATE 2
#define MAP_FIXED 16
#define pr_warn_ratelimited(...) do { } while (0)
#define IS_ERR_VALUE(x) ((unsigned long)(x) >= (unsigned long)-4095)
#undef IS_ERR
#define IS_ERR(p) IS_ERR_VALUE((unsigned long)(void *)(p))
#define init_task_work(cb, fn) ((cb)->func = (fn))
#define TWA_RESUME 1

struct path_stub { const char *name; };
struct file { struct path_stub f_path; long size; };
struct vm_area_struct {
	unsigned long vm_start;
	unsigned long vm_end;
	struct file *vm_file;
};
struct mm_struct { struct vm_area_struct *v; int n; };
struct callback_head { void (*func)(struct callback_head *); };

#define VMA_ITERATOR(name, mm, addr) int name = 0
#define for_each_vma(vmi, vma) \
	for (; (vmi) < current->mm->n ? ((vma) = &current->mm->v[vmi], 1) : 0; (vmi)++)
#define mmap_read_lock_killable(mm) 0
#define mmap_read_unlock(mm) do { } while (0)
#define d_path(p, buf, len) ((p)->name)
#define file_inode(f) (f)
#define i_size_read(f) ((f)->size)
#define filp_close(f, x) do { } while (0)

struct kg_remap_log { char src[128]; unsigned long addr; unsigned long len; };
extern struct kg_remap_log kg_remaps[16];
extern int kg_remap_n;
extern int kg_open_fail;
extern long kg_open_size;

static inline struct file *filp_open(const char *p, int f, int m)
{
	static struct file cur;
	(void)f; (void)m;
	if (kg_open_fail)
		return (struct file *)(long)-2;
	cur.f_path.name = p;
	cur.size = kg_open_size;
	return &cur;
}

static inline unsigned long vm_mmap(struct file *f, unsigned long addr,
				    unsigned long len, unsigned long prot,
				    unsigned long flags, unsigned long off)
{
	(void)prot; (void)flags; (void)off;
	if (kg_remap_n < 16) {
		strscpy(kg_remaps[kg_remap_n].src, f->f_path.name, 128);
		kg_remaps[kg_remap_n].addr = addr;
		kg_remaps[kg_remap_n].len = len;
		kg_remap_n++;
	}
	return addr;
}

static inline int kg_task_work_add(struct callback_head *cb)
{
	cb->func(cb);
	return 0;
}
#define task_work_add(t, cb, m) kg_task_work_add(cb)
#endif
