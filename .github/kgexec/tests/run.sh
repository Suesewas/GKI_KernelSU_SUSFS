#!/bin/sh
set -e
cd "$(dirname "$0")"
sed 's|^#include <linux/\(.*\)\.h>$|#include "linux/\1.h"|' ../kg_prop.c | grep -v "^#define pr_fmt" > kg_prop_body.c
cc -I. -std=gnu11 -O1 -o kg_prop_bench kg_prop_bench.c
./kg_prop_bench
rm -f kg_prop_body.c kg_prop_bench
