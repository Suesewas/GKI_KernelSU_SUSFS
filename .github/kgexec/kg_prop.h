#ifndef _LINUX_KG_PROP_H
#define _LINUX_KG_PROP_H

#include <linux/jump_label.h>

struct filename;

DECLARE_STATIC_KEY_FALSE(kg_prop_key);

struct filename *kg_prop_redirect(struct filename *name);

#endif
