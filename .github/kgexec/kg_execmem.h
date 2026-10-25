#ifndef _LINUX_KG_EXECMEM_H
#define _LINUX_KG_EXECMEM_H

#include <linux/types.h>
#include <linux/jump_label.h>

struct file;
struct vm_area_struct;

DECLARE_STATIC_KEY_FALSE(kg_execmem_key);

bool kg_execmem_block_mmap(struct file *file, unsigned long prot);
bool kg_execmem_block_mprotect(struct vm_area_struct *vma,
			       unsigned long newflags);
bool kg_dex_block_open(struct file *file);
bool kg_execmem_sys_active(void);

#endif
