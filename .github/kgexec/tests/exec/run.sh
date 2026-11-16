#!/bin/sh
set -e
cd "$(dirname "$0")"
sed 's|^#include <linux/\(.*\)\.h>$|#include "linux/\1.h"|' ../../kg_execmem.c \
    | grep -v "^#define pr_fmt" > kg_execmem_body.c
cc -I. -std=gnu11 -O1 -Wno-unused-function -o kg_execmem_bench kg_execmem_bench.c
./kg_execmem_bench
rm -f kg_execmem_body.c kg_execmem_bench
