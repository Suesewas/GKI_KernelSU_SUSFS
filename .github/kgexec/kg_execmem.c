// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "kg_execmem: " fmt

#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/kg_cred.h>
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

#include <linux/elf.h>
#include <linux/jiffies.h>
#include <linux/mmap_lock.h>
#include <linux/spinlock.h>
#include <linux/uprobes.h>

#include <asm/compat.h>

#include <asm/unaligned.h>

#include <linux/kg_execmem.h>

#ifdef CONFIG_ARM64
static inline unsigned long kg_art_arg(struct pt_regs *regs, int n)
{
	return regs->regs[n];
}

static inline void kg_art_set_arg(struct pt_regs *regs, int n, unsigned long v)
{
	regs->regs[n] = v;
}
#else
static inline unsigned long kg_art_arg(struct pt_regs *regs, int n)
{
	return 0;
}

static inline void kg_art_set_arg(struct pt_regs *regs, int n, unsigned long v)
{
}
#endif

#define KG_ABI		9
#define KG_MAX_APPS	512
#define KG_SEEN_MAX	256
#define KG_APP_MIN	10000
#define KG_SYS_MIN	1000
#define KG_SYS_MAX	9999
#define KG_APP_MAX	19999
#define KG_SDK_MIN	20000
#define KG_SDK_MAX	29999
#define KG_SDK_OFF	10000
#define KG_ISO_MIN	90000
#define KG_ISO_MAX	99999
#define KG_USER_OFF	100000
#define KG_FLAG_MEM	1
#define KG_FLAG_FILE	2
#define KG_FLAG_WATCH	4
#define KG_FLAG_DEX	8
#define KG_FLAG_DEXFILE	16
#define KG_SEEN_MEM	32
#define KG_FLAG_ALL	(KG_FLAG_MEM | KG_FLAG_FILE | KG_FLAG_WATCH | KG_FLAG_DEX | \
			 KG_FLAG_DEXFILE)
#define KG_DEX_PEEK	4096
#define KG_CD_MAX	(64 * 1024)
#define KG_CMD_MAX	256
#define KG_OUT_MAX	16384
#define KG_PATH_MAX	160
#define KG_LOC_MAX	256
#define KG_ELF_MAX	(1 << 20)

struct kg_table {
	struct rcu_head rcu;
	int count;
	u32 id[KG_MAX_APPS];
	u8 flags[KG_MAX_APPS];
};

DEFINE_STATIC_KEY_FALSE(kg_execmem_key);

static struct kg_table __rcu *kg_table;
static DEFINE_MUTEX(kg_lock);
static bool kg_sealed;
static u8 kg_default;
static u8 kg_sys_flags;

bool kg_execmem_sys_active(void)
{
	return READ_ONCE(kg_sys_flags) != 0;
}

static u8 kg_sys_now(u32 uid)
{
	u8 f = READ_ONCE(kg_sys_flags);

	if (!f)
		return 0;

	if (uid < KG_SYS_MIN || uid > KG_SYS_MAX)
		return 0;

	if (!kg_cred_active())
		return 0;

	if (kg_cred_is_system_server())
		return 0;

	return f;
}

static u32 kg_seen[KG_SEEN_MAX];
static u8 kg_seen_why[KG_SEEN_MAX];
static atomic_t kg_seen_n = ATOMIC_INIT(0);

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
	"/data/misc/apexdata/com.android.art/dalvik-cache/",
};

static u8 kg_flags_now(u32 *out_appid, bool *soft)
{
	struct kg_table *t;
	u32 appid;
	u8 flags = 0;
	bool found = false;
	int i;

	appid = from_kuid(&init_user_ns, current_uid()) % KG_USER_OFF;
	if (appid < KG_APP_MIN)
		return kg_sys_now(appid);
	if (appid > KG_APP_MAX) {
		if (appid >= KG_SDK_MIN && appid <= KG_SDK_MAX) {
			appid -= KG_SDK_OFF;
		} else if (appid >= KG_ISO_MIN) {
			if (out_appid)
				*out_appid = appid;
			if (soft)
				*soft = true;

			return READ_ONCE(kg_default);
		} else {
			return 0;
		}
	}

	if (out_appid)
		*out_appid = appid;

	rcu_read_lock();
	t = rcu_dereference(kg_table);
	if (t) {
		for (i = 0; i < t->count; i++) {
			if (t->id[i] == appid) {
				flags = t->flags[i];
				found = true;
				break;
			}
		}
	}
	rcu_read_unlock();

	return found ? flags : READ_ONCE(kg_default);
}

static void kg_mark_seen(u32 appid, u8 why)
{
	int n, i;

	if (appid < KG_APP_MIN || appid > KG_ISO_MAX)
		return;

	n = atomic_read(&kg_seen_n);
	if (n > KG_SEEN_MAX)
		n = KG_SEEN_MAX;

	for (i = 0; i < n; i++) {
		if (READ_ONCE(kg_seen[i]) == appid) {
			if (!(READ_ONCE(kg_seen_why[i]) & why))
				WRITE_ONCE(kg_seen_why[i],
					   READ_ONCE(kg_seen_why[i]) | why);
			return;
		}
	}

	i = atomic_fetch_inc(&kg_seen_n);
	if (i >= KG_SEEN_MAX) {
		atomic_set(&kg_seen_n, KG_SEEN_MAX);
		return;
	}

	WRITE_ONCE(kg_seen_why[i], why);
	WRITE_ONCE(kg_seen[i], appid);
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
		if (strcmp(name, kg_jit_name[i]) == 0)
			return true;
	}

	return false;
}

static bool kg_mem_like(struct file *file)
{
	struct inode *inode;

	if (!file)
		return true;

	inode = file_inode(file);
	if (!inode || !inode->i_sb)
		return false;

	switch (inode->i_sb->s_magic) {
	case TMPFS_MAGIC:
	case HUGETLBFS_MAGIC:
	case RAMFS_MAGIC:
		return true;
	default:
		return false;
	}
}

static bool kg_path_deleted(const char *p)
{
	size_t n = strlen(p);
	static const char tail[] = " (deleted)";
	size_t t = sizeof(tail) - 1;

	return n > t && strcmp(p + n - t, tail) == 0;
}

static bool kg_in_allow(const char *p)
{
	size_t i;

	if (kg_path_deleted(p))
		return false;

	for (i = 0; i < ARRAY_SIZE(kg_allow); i++) {
		if (strncmp(p, kg_allow[i], strlen(kg_allow[i])) == 0)
			return true;
	}

	return false;
}

static bool kg_path_ok(struct file *file, u8 flags)
{
	char *buf, *p;
	bool ok = false;

	(void)flags;

	buf = (char *)__get_free_page(GFP_KERNEL);
	if (!buf)
		return false;

	p = d_path(&file->f_path, buf, PAGE_SIZE);
	if (IS_ERR(p)) {
		free_page((unsigned long)buf);
		return false;
	}

	ok = kg_in_allow(p);

	if (!ok)
		pr_warn_ratelimited("uid %u comm %s exec map denied: %s\n",
				    from_kuid(&init_user_ns, current_uid()),
				    current->comm, p);

	free_page((unsigned long)buf);
	return ok;
}

static bool kg_names_dex(const char *buf, size_t n)
{
	size_t i;

	for (i = 0; i + 11 <= n; i++) {
		if (buf[i] != 'c' || memcmp(buf + i, "classes", 7))
			continue;
		{
			size_t j = i + 7;

			while (j < n && buf[j] >= '0' && buf[j] <= '9')
				j++;
			if (j + 4 <= n && memcmp(buf + j, ".dex", 4) == 0)
				return true;
		}
	}

	return false;
}

static bool kg_buf_is_code(const char *buf, size_t n)
{
	if (n >= 4) {
		if (memcmp(buf, "dex\n", 4) == 0)
			return true;
		if (memcmp(buf, "cdex", 4) == 0)
			return true;
		if (memcmp(buf, "vdex", 4) == 0)
			return true;
		if (memcmp(buf, "dey\n", 4) == 0)
			return true;
	}

	if (n >= 4 && memcmp(buf, "PK\x03\x04", 4) != 0)
		return false;

	if (n < 30)
		return false;

	return kg_names_dex(buf, n);
}

static bool kg_zip_has_dex(struct file *file, char *buf)
{
	loff_t size = i_size_read(file_inode(file));
	loff_t tail, pos, cd;
	u32 cdoff, cdsize, left;
	ssize_t n;
	int i, eocd = -1;

	if (size < 22)
		return false;

	tail = size > KG_DEX_PEEK ? size - KG_DEX_PEEK : 0;
	pos = tail;
	n = kernel_read(file, buf, KG_DEX_PEEK, &pos);
	if (n < 22)
		return false;

	for (i = (int)n - 22; i >= 0; i--) {
		if (memcmp(buf + i, "PK\x05\x06", 4) == 0) {
			eocd = i;
			break;
		}
	}
	if (eocd < 0)
		return kg_names_dex(buf, (size_t)n);

	cdsize = get_unaligned_le32(buf + eocd + 12);
	cdoff = get_unaligned_le32(buf + eocd + 16);
	if (!cdsize || (loff_t)cdoff >= size)
		return kg_names_dex(buf, (size_t)n);

	left = cdsize > KG_CD_MAX ? KG_CD_MAX : cdsize;
	cd = cdoff;
	while (left) {
		u32 want = left > KG_DEX_PEEK ? KG_DEX_PEEK : left;

		pos = cd;
		n = kernel_read(file, buf, want, &pos);
		if (n <= 0)
			break;
		if (kg_names_dex(buf, (size_t)n))
			return true;
		if ((u32)n < want)
			break;
		/* шаг с перехлёстом, чтобы имя не разорвалось на границе */
		if ((u32)n <= 32)
			break;
		cd += n - 32;
		left -= (u32)n - 32;
	}

	return false;
}

bool kg_dex_block_open(struct file *file)
{
	u32 appid = 0;
	u8 flags;
	bool soft = false;
	char *buf, *p;
	loff_t pos = 0;
	ssize_t n;
	bool bad = false;

	if (!file)
		return false;

	flags = kg_flags_now(&appid, &soft);
	if (!(flags & KG_FLAG_DEXFILE))
		return false;

	if (!(file->f_mode & FMODE_READ))
		return false;
	if (!file_inode(file) || !S_ISREG(file_inode(file)->i_mode))
		return false;

	buf = (char *)__get_free_page(GFP_KERNEL);
	if (!buf)
		return false;

	p = d_path(&file->f_path, buf, PAGE_SIZE);
	if (IS_ERR(p) || kg_in_allow(p)) {
		free_page((unsigned long)buf);
		return false;
	}

	n = kernel_read(file, buf, 8, &pos);
	if (n >= 4 && kg_buf_is_code(buf, (size_t)n)) {
		bad = true;
	} else if (n >= 4 && memcmp(buf, "PK\x03\x04", 4) == 0) {
		pos = 0;
		n = kernel_read(file, buf, KG_DEX_PEEK, &pos);
		if (n > 0 && kg_buf_is_code(buf, (size_t)n))
			bad = true;
		if (!bad)
			bad = kg_zip_has_dex(file, buf);
	}

	if (bad) {
		kg_mark_seen(appid, KG_FLAG_DEXFILE);
		p = d_path(&file->f_path, buf, PAGE_SIZE);
		if (soft) {
			pr_info_ratelimited("uid %u comm %s dex open observed: %s\n",
					    from_kuid(&init_user_ns, current_uid()),
					    current->comm, IS_ERR(p) ? "?" : p);
			bad = false;
		} else {
			pr_warn_ratelimited("uid %u comm %s dex open denied: %s\n",
					    from_kuid(&init_user_ns, current_uid()),
					    current->comm, IS_ERR(p) ? "?" : p);
		}
	}

	free_page((unsigned long)buf);

	return bad;
}

static bool kg_mem_verdict(u32 appid, u8 flags, bool soft, u8 mask,
			   const char *what)
{
	if (!(flags & mask)) {
		if (flags & KG_FLAG_WATCH) {
			kg_mark_seen(appid, KG_FLAG_MEM);
			pr_info_ratelimited("uid %u comm %s %s observed\n",
					    from_kuid(&init_user_ns, current_uid()),
					    current->comm, what);
		}
		return false;
	}

	kg_mark_seen(appid, KG_FLAG_MEM);

	if ((flags & KG_FLAG_WATCH) || soft) {
		pr_info_ratelimited("uid %u comm %s %s observed\n",
				    from_kuid(&init_user_ns, current_uid()),
				    current->comm, what);
		return false;
	}

	pr_warn_ratelimited("uid %u comm %s %s denied\n",
			    from_kuid(&init_user_ns, current_uid()),
			    current->comm, what);

	return true;
}

static bool kg_file_verdict(u32 appid, u8 flags, bool soft, struct file *file)
{
	if (!(flags & KG_FLAG_FILE))
		return false;

	if (kg_path_ok(file, flags))
		return false;

	kg_mark_seen(appid, KG_FLAG_FILE);

	return !soft;
}

bool kg_execmem_block_mmap(struct file *file, unsigned long prot)
{
	u32 appid = 0;
	u8 flags;
	bool soft = false;

	if (!(prot & PROT_EXEC))
		return false;

	flags = kg_flags_now(&appid, &soft);
	if (!flags)
		return false;

	if (file && kg_jit_file(file) && !(flags & KG_FLAG_MEM))
		return false;

	if (prot & PROT_WRITE)
		return kg_mem_verdict(appid, flags, soft, KG_FLAG_MEM,
				      "writable exec map");

	if (!file)
		return kg_mem_verdict(appid, flags, soft, KG_FLAG_MEM,
				      "anonymous exec map");

	if (kg_mem_like(file))
		return kg_mem_verdict(appid, flags, soft,
				      KG_FLAG_MEM | KG_FLAG_FILE,
				      "exec map of memory file");

	return kg_file_verdict(appid, flags, soft, file);
}

bool kg_execmem_block_mprotect(struct vm_area_struct *vma,
			       unsigned long newflags)
{
	u32 appid = 0;
	u8 flags;
	bool soft = false;
	bool gain_exec, wx;

	gain_exec = (newflags & VM_EXEC) && !(vma->vm_flags & VM_EXEC);
	wx = (newflags & VM_EXEC) && (newflags & VM_WRITE) &&
	     !((vma->vm_flags & VM_EXEC) && (vma->vm_flags & VM_WRITE));

	if (!gain_exec && !wx)
		return false;

	flags = kg_flags_now(&appid, &soft);
	if (!flags)
		return false;

	if (vma->vm_file && kg_jit_file(vma->vm_file) &&
	    !(flags & KG_FLAG_MEM))
		return false;

	if (wx)
		return kg_mem_verdict(appid, flags, soft, KG_FLAG_MEM,
				      "writable exec remap");

	if (!vma->vm_file)
		return kg_mem_verdict(appid, flags, soft, KG_FLAG_MEM,
				      "anonymous exec remap");

	if (kg_mem_like(vma->vm_file))
		return kg_mem_verdict(appid, flags, soft,
				      KG_FLAG_MEM | KG_FLAG_FILE,
				      "exec remap of memory file");

	return kg_file_verdict(appid, flags, soft, vma->vm_file);
}

#ifdef CONFIG_UPROBES

static const char kg_art_sym_pre[] = "_ZN3art13DexFileLoader10OpenCommonE";
static const char kg_art_sym_want[] = "shared_ptrINS_16DexFileContainerEEE";

static const char kg_art_anon[] = "Anonymous-DexFile@";

static struct inode *kg_art_inode;
static loff_t kg_art_off_common;
static bool kg_art_on;
static char kg_art_file[KG_PATH_MAX];
static atomic_t kg_art_hits = ATOMIC_INIT(0);
static DEFINE_MUTEX(kg_art_lock);

static int kg_read_cxx_string(unsigned long addr, char *out, size_t max)
{
	u8 hdr[24];
	u64 size, ptr;

	if (!addr || max < 2)
		return -EINVAL;

	if (copy_from_user(hdr, (void __user *)addr, sizeof(hdr)))
		return -EFAULT;

	if (hdr[0] & 1) {
		memcpy(&size, hdr + 8, sizeof(size));
		memcpy(&ptr, hdr + 16, sizeof(ptr));
		if (!ptr || !size)
			return -EINVAL;
		if (size >= (u64)max)
			size = (u64)max - 1;
		if (copy_from_user(out, (void __user *)(unsigned long)ptr, size))
			return -EFAULT;
		out[size] = '\0';
		return 0;
	}

	size = hdr[0] >> 1;
	if (size > 22)
		return -EINVAL;
	if (size >= (u64)max)
		size = (u64)max - 1;
	memcpy(out, hdr + 1, size);
	out[size] = '\0';

	return 0;
}

static const char *kg_basename(const char *p)
{
	const char *s = strrchr(p, '/');

	return s ? s + 1 : p;
}

static bool kg_loc_denied(const char *loc, u8 *why)
{
	const char *base = kg_basename(loc);

	if (strncmp(base, kg_art_anon, sizeof(kg_art_anon) - 1) == 0) {
		*why = KG_SEEN_MEM;
		return true;
	}

	return false;
}

static int kg_art_common_handler(struct uprobe_consumer *uc,
				 struct pt_regs *regs)
{
	char loc[KG_LOC_MAX];
	u32 appid = 0;
	u8 flags, why = KG_FLAG_DEX;
	bool soft = false;

	if (is_compat_task())
		return 0;

	flags = kg_flags_now(&appid, &soft);
	if (!(flags & KG_FLAG_DEX))
		return 0;

	if (kg_read_cxx_string(kg_art_arg(regs, 3), loc, sizeof(loc)))
		return 0;

	if (!kg_loc_denied(loc, &why))
		return 0;

	if (!kg_art_arg(regs, 2))
		return 0;

	kg_mark_seen(appid, why);

	if (soft) {
		pr_info_ratelimited("uid %u comm %s dex load observed: %s\n",
				    from_kuid(&init_user_ns, current_uid()),
				    current->comm, loc);
		return 0;
	}

	kg_art_set_arg(regs, 1, kg_art_arg(regs, 1) + 1);
	atomic_inc(&kg_art_hits);
	pr_warn_ratelimited("uid %u comm %s dex load denied: %s\n",
			    from_kuid(&init_user_ns, current_uid()),
			    current->comm, loc);

	return 0;
}

static struct uprobe_consumer kg_art_uc_common = {
	.handler = kg_art_common_handler,
};

static int kg_read_at(struct file *f, loff_t pos, void *buf, size_t n)
{
	ssize_t r = kernel_read(f, buf, n, &pos);

	return (r == (ssize_t)n) ? 0 : -EIO;
}

static int kg_elf_offsets(struct file *f, loff_t *common)
{
	struct elf64_hdr eh;
	struct elf64_phdr *ph = NULL;
	struct elf64_shdr *sh = NULL;
	struct elf64_sym *sym = NULL;
	char *str = NULL;
	size_t phsz, shsz, symsz, strsz = 0;
	loff_t stroff = 0;
	int ret, i, n;

	*common = 0;

	ret = kg_read_at(f, 0, &eh, sizeof(eh));
	if (ret)
		return ret;
	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
		return -EINVAL;
	if (eh.e_ident[EI_CLASS] != ELFCLASS64)
		return -EINVAL;
	if (!eh.e_phnum || !eh.e_shnum)
		return -EINVAL;
	if (eh.e_phentsize != sizeof(*ph) || eh.e_shentsize != sizeof(*sh))
		return -EINVAL;
	if (eh.e_phnum > 128 || eh.e_shnum > 256)
		return -EINVAL;

	phsz = (size_t)eh.e_phnum * sizeof(*ph);
	shsz = (size_t)eh.e_shnum * sizeof(*sh);

	ph = kvmalloc(phsz, GFP_KERNEL);
	sh = kvmalloc(shsz, GFP_KERNEL);
	if (!ph || !sh) {
		ret = -ENOMEM;
		goto out;
	}

	ret = kg_read_at(f, eh.e_phoff, ph, phsz);
	if (ret)
		goto out;
	ret = kg_read_at(f, eh.e_shoff, sh, shsz);
	if (ret)
		goto out;

	for (i = 0; i < eh.e_shnum; i++) {
		if (sh[i].sh_type != SHT_DYNSYM)
			continue;
		if (sh[i].sh_entsize != sizeof(*sym))
			continue;
		if (sh[i].sh_link >= eh.e_shnum)
			continue;
		symsz = sh[i].sh_size;
		strsz = sh[sh[i].sh_link].sh_size;
		stroff = sh[sh[i].sh_link].sh_offset;
		if (!symsz || !strsz || symsz > KG_ELF_MAX || strsz > KG_ELF_MAX)
			continue;
		sym = kvmalloc(symsz, GFP_KERNEL);
		str = kvmalloc(strsz, GFP_KERNEL);
		if (!sym || !str) {
			ret = -ENOMEM;
			goto out;
		}
		ret = kg_read_at(f, sh[i].sh_offset, sym, symsz);
		if (ret)
			goto out;
		ret = kg_read_at(f, stroff, str, strsz);
		if (ret)
			goto out;
		break;
	}

	if (!sym || !str) {
		ret = -ENOENT;
		goto out;
	}

	str[strsz - 1] = '\0';
	n = symsz / sizeof(*sym);

	for (i = 0; i < n; i++) {
		const char *name;
		loff_t off = -1;
		int j;

		if (!sym[i].st_name || sym[i].st_name >= strsz || !sym[i].st_value)
			continue;
		name = str + sym[i].st_name;

		if (strncmp(name, kg_art_sym_pre, sizeof(kg_art_sym_pre) - 1) != 0)
			continue;
		if (!strstr(name, kg_art_sym_want)) {
			if (!*common)
				*common = 0;
			continue;
		}

		for (j = 0; j < eh.e_phnum; j++) {
			u64 va = ph[j].p_vaddr;

			if (ph[j].p_type != PT_LOAD)
				continue;
			if (sym[i].st_value < va ||
			    sym[i].st_value >= va + ph[j].p_filesz)
				continue;
			off = ph[j].p_offset + (sym[i].st_value - va);
			break;
		}

		if (off < 0)
			continue;

		*common = off;
		break;
	}

	ret = *common ? 0 : -ENOENT;

out:
	kvfree(ph);
	kvfree(sh);
	kvfree(sym);
	kvfree(str);

	return ret;
}

static void kg_art_off(void)
{
	if (!kg_art_on)
		return;

	uprobe_unregister(kg_art_inode, kg_art_off_common, &kg_art_uc_common);
	iput(kg_art_inode);
	kg_art_inode = NULL;
	kg_art_off_common = 0;
	kg_art_file[0] = '\0';
	kg_art_on = false;
	pr_warn("art hooks removed\n");
}

static int kg_art_arm(const char *path)
{
	struct file *f;
	struct inode *inode;
	loff_t common = 0;
	int ret;

	if (!path[0] || path[0] != '/')
		return -EINVAL;

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);

	ret = kg_elf_offsets(f, &common);
	if (ret) {
		filp_close(f, NULL);
		return ret;
	}

	inode = igrab(file_inode(f));
	filp_close(f, NULL);
	if (!inode)
		return -ENOENT;

	kg_art_off();

	ret = uprobe_register(inode, common, &kg_art_uc_common);
	if (ret) {
		iput(inode);
		return ret;
	}

	kg_art_inode = inode;
	kg_art_off_common = common;
	strscpy(kg_art_file, path, sizeof(kg_art_file));
	kg_art_on = true;
	atomic_set(&kg_art_hits, 0);

	pr_warn("art hook armed on %s common=%#llx\n",
		path, (unsigned long long)common);

	return 0;
}

static int kg_art_cmd(const char *arg)
{
	int ret;

	mutex_lock(&kg_art_lock);
	if (kg_sealed) {
		mutex_unlock(&kg_art_lock);
		return -EPERM;
	}
	if (strcmp(arg, "off") == 0) {
		kg_art_off();
		ret = 0;
	} else {
		ret = kg_art_arm(arg);
	}
	mutex_unlock(&kg_art_lock);

	return ret;
}

static int kg_art_report(char *out, size_t max)
{
	int n;

	mutex_lock(&kg_art_lock);
	n = scnprintf(out, max, "art %d %d %s\n", kg_art_on ? 1 : 0,
		      atomic_read(&kg_art_hits),
		      kg_art_on ? kg_art_file : "-");
	mutex_unlock(&kg_art_lock);

	return n;
}

#else /* CONFIG_UPROBES */

static int kg_art_cmd(const char *arg)
{
	return -ENOTSUPP;
}

static int kg_art_report(char *out, size_t max)
{
	return scnprintf(out, max, "art 0 0 -\n");
}

#endif /* CONFIG_UPROBES */

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
	} else {
		t->count = 0;
	}

	return t;
}

static void kg_update_key(struct kg_table *t)
{
	bool on;
	int i;

	on = READ_ONCE(kg_default) != 0 || READ_ONCE(kg_sys_flags) != 0;

	if (!on && t) {
		for (i = 0; i < t->count; i++) {
			if (t->flags[i] != 0) {
				on = true;
				break;
			}
		}
	}

	if (on)
		static_branch_enable(&kg_execmem_key);
	else
		static_branch_disable(&kg_execmem_key);
}

static void kg_publish(struct kg_table *t)
{
	struct kg_table *old;

	old = rcu_dereference_protected(kg_table, lockdep_is_held(&kg_lock));
	rcu_assign_pointer(kg_table, t);

	kg_update_key(t);

	if (old)
		kfree_rcu(old, rcu);
}

static int kg_set_default(u32 flags)
{
	struct kg_table *t;

	if (flags > KG_FLAG_ALL)
		return -EINVAL;

	mutex_lock(&kg_lock);
	if (kg_sealed) {
		mutex_unlock(&kg_lock);
		return -EPERM;
	}

	WRITE_ONCE(kg_default, (u8)flags);
	t = rcu_dereference_protected(kg_table, lockdep_is_held(&kg_lock));
	kg_update_key(t);
	mutex_unlock(&kg_lock);

	return 0;
}

static int kg_set_sys(u32 flags)
{
	if (flags > KG_FLAG_ALL)
		return -EINVAL;

	if (flags && !kg_cred_active()) {
		pr_warn("the profile for system uids needs the kg_cred layer on, otherwise system_server cannot be told apart\n");
		return -EBUSY;
	}

	mutex_lock(&kg_lock);
	if (kg_sealed) {
		mutex_unlock(&kg_lock);
		return -EPERM;
	}
	WRITE_ONCE(kg_sys_flags, (u8)flags);
	kg_update_key(rcu_dereference_protected(kg_table,
					       lockdep_is_held(&kg_lock)));
	mutex_unlock(&kg_lock);

	return 0;
}

static int kg_add(u32 appid, u32 flags)
{
	struct kg_table *old, *t;
	int i;

	if (appid < KG_APP_MIN || appid > KG_APP_MAX)
		return -ERANGE;
	if (flags > KG_FLAG_ALL)
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

	WRITE_ONCE(kg_default, 0);
	WRITE_ONCE(kg_sys_flags, 0);
	kg_publish(t);
	mutex_unlock(&kg_lock);

	return 0;
}

static int kg_seen_del(u32 appid)
{
	int n, i;

	if (appid < KG_APP_MIN || appid > KG_APP_MAX)
		return -ERANGE;

	n = atomic_read(&kg_seen_n);
	if (n > KG_SEEN_MAX)
		n = KG_SEEN_MAX;

	for (i = 0; i < n; i++) {
		if (READ_ONCE(kg_seen[i]) != appid)
			continue;
		WRITE_ONCE(kg_seen_why[i], 0);
		WRITE_ONCE(kg_seen[i], 0);
		return 0;
	}

	return 0;
}

static int kg_seen_clear(void)
{
	atomic_set(&kg_seen_n, 0);

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
	int n = 0, i, ns;
	ssize_t ret;

	out = kmalloc(KG_OUT_MAX, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	mutex_lock(&kg_lock);
	t = rcu_dereference_protected(kg_table, lockdep_is_held(&kg_lock));
	n += scnprintf(out + n, KG_OUT_MAX - n, "abi %d\n", KG_ABI);
	n += scnprintf(out + n, KG_OUT_MAX - n, "sealed %d\n", kg_sealed ? 1 : 0);
	n += scnprintf(out + n, KG_OUT_MAX - n, "default %u\n",
		       READ_ONCE(kg_default));
	n += scnprintf(out + n, KG_OUT_MAX - n, "sys %u\n",
		       READ_ONCE(kg_sys_flags));
	n += scnprintf(out + n, KG_OUT_MAX - n, "count %d\n", t ? t->count : 0);
	n += kg_art_report(out + n, KG_OUT_MAX - n);
	if (t) {
		for (i = 0; i < t->count && n < KG_OUT_MAX - 32; i++)
			n += scnprintf(out + n, KG_OUT_MAX - n, "%u %u\n",
				       t->id[i], t->flags[i]);
	}
	mutex_unlock(&kg_lock);

	ns = atomic_read(&kg_seen_n);
	if (ns > KG_SEEN_MAX)
		ns = KG_SEEN_MAX;
	for (i = 0; i < ns && n < KG_OUT_MAX - 32; i++)
		n += scnprintf(out + n, KG_OUT_MAX - n, "seen %u %u\n",
			       READ_ONCE(kg_seen[i]),
			       READ_ONCE(kg_seen_why[i]));

	ret = simple_read_from_buffer(ubuf, len, off, out, n);
	kfree(out);

	return ret;
}

static ssize_t kg_proc_write(struct file *file, const char __user *ubuf,
			     size_t len, loff_t *off)
{
	char cmd[KG_CMD_MAX];
	char verb[16];
	char arg[KG_PATH_MAX];
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
	else if (strcmp(verb, "default") == 0 && got >= 2)
		ret = kg_set_default(appid);
	else if (strcmp(verb, "sys") == 0 && got >= 2)
		ret = kg_set_sys(appid);
	else if (strcmp(verb, "clear") == 0)
		ret = kg_clear();
	else if (strcmp(verb, "seal") == 0)
		ret = kg_seal();
	else if (strcmp(verb, "art") == 0 &&
		 sscanf(cmd, "%15s %159s", verb, arg) == 2)
		ret = kg_art_cmd(arg);
	else if (strcmp(verb, "seen") == 0 &&
		 sscanf(cmd, "%15s %159s %u", verb, arg, &appid) >= 2) {
		if (strcmp(arg, "clear") == 0)
			ret = kg_seen_clear();
		else if (strcmp(arg, "del") == 0 &&
			 sscanf(cmd, "%15s %159s %u", verb, arg, &appid) == 3)
			ret = kg_seen_del(appid);
		else
			ret = -EINVAL;
	}
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
