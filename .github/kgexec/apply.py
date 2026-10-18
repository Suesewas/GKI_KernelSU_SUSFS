#!/usr/bin/env python3
import os
import shutil
import sys

INCLUDE_ANCHOR = "#include <linux/mman.h>\n"
INCLUDE_LINE = "#include <linux/kg_execmem.h>\n"

MMAP_ANCHOR = "\t/* force arch specific MAP_FIXED handling in get_unmapped_area */\n"
MMAP_HOOK = (
    "\tif (static_branch_unlikely(&kg_execmem_key) &&\n"
    "\t    kg_execmem_block_mmap(file, prot))\n"
    "\t\treturn -EACCES;\n"
    "\n"
)

MPROTECT_ANCHOR = "\t\terror = security_file_mprotect(vma, reqprot, prot);\n"
MPROTECT_HOOK = (
    "\t\tif (static_branch_unlikely(&kg_execmem_key) &&\n"
    "\t\t    kg_execmem_block_mprotect(vma, newflags)) {\n"
    "\t\t\terror = -EACCES;\n"
    "\t\t\tbreak;\n"
    "\t\t}\n"
    "\n"
)

MAKEFILE_LINE = "obj-y += kg_execmem.o\n"


def fail(msg):
    sys.stderr.write("kgexec: %s\n" % msg)
    sys.exit(1)


def read(path):
    if not os.path.isfile(path):
        fail("missing %s" % path)
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        return fh.read()


def write(path, data):
    with open(path, "w", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write(data)


def insert_before(src, anchor, block, what):
    if src.count(anchor) != 1:
        fail("anchor for %s found %d times" % (what, src.count(anchor)))
    return src.replace(anchor, block + anchor, 1)


def insert_after(src, anchor, block, what):
    if anchor not in src:
        fail("anchor for %s not found" % what)
    return src.replace(anchor, anchor + block, 1)


def patch_c(path, hook_anchor, hook_block, what):
    src = read(path)
    if "kg_execmem" in src:
        print("kgexec: %s already patched" % what)
        return
    src = insert_after(src, INCLUDE_ANCHOR, INCLUDE_LINE, "%s include" % what)
    src = insert_before(src, hook_anchor, hook_block, "%s hook" % what)
    write(path, src)
    print("kgexec: patched %s" % what)


def patch_makefile(path):
    src = read(path)
    if MAKEFILE_LINE in src:
        print("kgexec: mm/Makefile already patched")
        return
    if not src.endswith("\n"):
        src += "\n"
    write(path, src + MAKEFILE_LINE)
    print("kgexec: patched mm/Makefile")


def verify(root):
    checks = [
        ("mm/mmap.c", "kg_execmem_block_mmap"),
        ("mm/mprotect.c", "kg_execmem_block_mprotect"),
        ("mm/mmap.c", "#include <linux/kg_execmem.h>"),
        ("mm/mprotect.c", "#include <linux/kg_execmem.h>"),
        ("mm/Makefile", "kg_execmem.o"),
        ("mm/kg_execmem.c", "DEFINE_STATIC_KEY_FALSE(kg_execmem_key)"),
        ("include/linux/kg_execmem.h", "DECLARE_STATIC_KEY_FALSE(kg_execmem_key)"),
    ]
    for rel, needle in checks:
        src = read(os.path.join(root, rel))
        if src.count(needle) != 1:
            fail("verify: %s in %s found %d times"
                 % (needle, rel, src.count(needle)))
    print("kgexec: verify ok")


def main():
    if len(sys.argv) != 3:
        fail("usage: apply.py <kernel_root> <source_dir>")
    root, srcdir = sys.argv[1], sys.argv[2]

    for rel in ("mm/mmap.c", "mm/mprotect.c", "mm/Makefile"):
        if not os.path.isfile(os.path.join(root, rel)):
            fail("not a kernel tree: %s" % root)

    shutil.copyfile(os.path.join(srcdir, "kg_execmem.c"),
                    os.path.join(root, "mm/kg_execmem.c"))
    os.makedirs(os.path.join(root, "include/linux"), exist_ok=True)
    shutil.copyfile(os.path.join(srcdir, "kg_execmem.h"),
                    os.path.join(root, "include/linux/kg_execmem.h"))

    patch_c(os.path.join(root, "mm/mmap.c"), MMAP_ANCHOR, MMAP_HOOK, "mm/mmap.c")
    patch_c(os.path.join(root, "mm/mprotect.c"), MPROTECT_ANCHOR,
            MPROTECT_HOOK, "mm/mprotect.c")
    patch_makefile(os.path.join(root, "mm/Makefile"))
    verify(root)


main()
