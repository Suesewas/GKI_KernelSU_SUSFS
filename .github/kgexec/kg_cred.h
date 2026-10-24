#ifndef _LINUX_KG_CRED_H
#define _LINUX_KG_CRED_H

#include <linux/jump_label.h>
#include <linux/types.h>

struct task_struct;
struct cred;

DECLARE_STATIC_KEY_FALSE(kg_cred_key);

void kg_cred_fork(struct task_struct *p);
void kg_cred_commit(struct task_struct *task, const struct cred *new);
void kg_cred_exit(struct task_struct *task);
void kg_cred_check(void);
bool kg_cred_block_module(void);
bool kg_cred_block_exec(const char *path);

#endif
