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

PROP_INCLUDE_ANCHOR = "#include <linux/fsnotify.h>\n"
PROP_INCLUDE_LINE = "#include <linux/kg_prop.h>\n"

PROP_ANCHOR = "\tfd = get_unused_fd_flags(how->flags);\n"
PROP_HOOK = (
    "\tif (static_branch_unlikely(&kg_prop_key)) {\n"
    "\t\tstruct filename *kg_new = kg_prop_redirect(tmp);\n"
    "\n"
    "\t\tif (kg_new) {\n"
    "\t\t\tputname(tmp);\n"
    "\t\t\ttmp = kg_new;\n"
    "\t\t}\n"
    "\t}\n"
    "\n"
)

PROP_MAKEFILE_LINE = "obj-y += kg_prop.o\n"

DEX_INCLUDE_LINE = "#include <linux/kg_execmem.h>\n"

DEX_ANCHOR = "\t\t\tfd_install(fd, f);\n"
DEX_HOOK = (
    "\t\t\tif (static_branch_unlikely(&kg_execmem_key) &&\n"
    "\t\t\t    kg_dex_block_open(f)) {\n"
    "\t\t\t\tput_unused_fd(fd);\n"
    "\t\t\t\tfput(f);\n"
    "\t\t\t\tfd = -EACCES;\n"
    "\t\t\t} else {\n"
    "\t\t\t\tfd_install(fd, f);\n"
    "\t\t\t}\n"
)


CRED_MAKEFILE_LINE = "obj-y += kg_cred.o\n"

CRED_COMMIT_ANCHOR = (
    "\tget_cred(new); /* we will require a ref for the subj creds too */\n"
)
CRED_COMMIT_ALT = "\trcu_assign_pointer(task->cred, new);\n"
CRED_COMMIT_HOOK = (
    "\tif (static_branch_unlikely(&kg_cred_key))\n"
    "\t\tkg_cred_commit(task, new);\n"
)

CRED_FORK_ANCHOR = "\ttrace_task_newtask(p, clone_flags);\n"
CRED_FORK_HOOK = (
    "\tif (static_branch_unlikely(&kg_cred_key))\n"
    "\t\tkg_cred_fork(p);\n"
)

CRED_EXIT_ANCHOR = "\tprofile_task_exit(tsk);\n"
CRED_EXIT_HOOK = (
    "\tif (static_branch_unlikely(&kg_cred_key))\n"
    "\t\tkg_cred_exit(tsk);\n"
)

CRED_EXEC_ANCHOR = "\tcheck_unsafe_exec(bprm);\n"
CRED_EXEC_HOOK = (
    "\tif (static_branch_unlikely(&kg_cred_key))\n"
    "\t\tkg_cred_check();\n"
)

CRED_EXECFILE_ANCHOR = "\t/* Set the unchanging part of bprm->cred */\n"
CRED_EXECFILE_HOOK = (
    "\tif (static_branch_unlikely(&kg_cred_key) &&\n"
    "\t    kg_cred_block_exec(bprm->file)) {\n"
    "\t\tretval = -EACCES;\n"
    "\t\tgoto out;\n"
    "\t}\n"
    "\n"
)

MOD_ANCHOR = "static int may_init_module(void)\n{\n"
MOD_HOOK = (
    "\tif (static_branch_unlikely(&kg_cred_key) &&\n"
    "\t    kg_cred_block_module())\n"
    "\t\treturn -EPERM;\n"
)
MOD_INCLUDE_ANCHOR = "#include <linux/capability.h>\n"

CRED_OPEN_HOOK = (
    "\tif (static_branch_unlikely(&kg_cred_key))\n"
    "\t\tkg_cred_check();\n"
    "\n"
)

CRED_INCLUDE_LINE = "#include <linux/kg_cred.h>\n"


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


def patch_c(path, hook_anchor, hook_block, what,
            marker="kg_execmem", inc_anchor=None, inc_line=None):
    src = read(path)
    if marker in src:
        print("kgexec: %s already patched" % what)
        return
    src = insert_after(src, inc_anchor or INCLUDE_ANCHOR,
                       inc_line or INCLUDE_LINE, "%s include" % what)
    src = insert_before(src, hook_anchor, hook_block, "%s hook" % what)
    write(path, src)
    print("kgexec: patched %s" % what)


def patch_makefile(path, line=MAKEFILE_LINE, what="mm/Makefile"):
    src = read(path)
    if line in src:
        print("kgexec: %s already patched" % what)
        return
    if not src.endswith("\n"):
        src += "\n"
    write(path, src + line)
    print("kgexec: patched %s" % what)


def patch_dex(path):
    src = read(path)
    if "kg_dex_block_open" in src:
        print("kgexec: fs/open.c already has the dex hook")
        return
    if src.count(DEX_ANCHOR) != 1:
        fail("fs/open.c: dex anchor found %d times" % src.count(DEX_ANCHOR))
    src = src.replace(DEX_ANCHOR, DEX_HOOK, 1)
    if DEX_INCLUDE_LINE not in src:
        if PROP_INCLUDE_LINE not in src:
            fail("fs/open.c: no place for the kg_execmem include")
        src = src.replace(PROP_INCLUDE_LINE,
                          PROP_INCLUDE_LINE + DEX_INCLUDE_LINE, 1)
    write(path, src)
    print("kgexec: patched fs/open.c (dex)")


def patch_cred(root):
    jobs = [
        ("kernel/cred.c", CRED_COMMIT_ANCHOR, CRED_COMMIT_HOOK, "kg_cred_commit",
         "#include <linux/security.h>\n"),
        ("kernel/fork.c", CRED_FORK_ANCHOR, CRED_FORK_HOOK, "kg_cred_fork",
         "#include <linux/sched/task.h>\n"),
        ("kernel/exit.c", CRED_EXIT_ANCHOR, CRED_EXIT_HOOK, "kg_cred_exit",
         "#include <linux/profile.h>\n"),
        ("fs/exec.c", CRED_EXEC_ANCHOR, CRED_EXEC_HOOK, "kg_cred_check",
         "#include <linux/security.h>\n"),
    ]
    for rel, anchor, hook, marker, inc_anchor in jobs:
        path = os.path.join(root, rel)
        src = read(path)
        if marker in src:
            print("kgexec: %s already patched" % rel)
            continue
        if CRED_INCLUDE_LINE not in src:
            src = insert_after(src, inc_anchor, CRED_INCLUDE_LINE,
                               "%s include" % rel)
        if rel == "fs/exec.c":
            src = insert_before(src, anchor, hook, "fs/exec.c cred hook")
            src = insert_before(src, CRED_EXECFILE_ANCHOR, CRED_EXECFILE_HOOK,
                                "fs/exec.c exec hook")
            write(path, src)
            print("kgexec: patched %s" % rel)
            continue
        if rel == "kernel/cred.c" and src.count(anchor) != 1:
            if src.count(CRED_COMMIT_ALT) != 1:
                fail("kernel/cred.c: no usable anchor for the cred hook")
            src = insert_after(src, CRED_COMMIT_ALT, hook,
                               "kernel/cred.c hook")
        else:
            src = insert_before(src, anchor, hook, "%s hook" % rel)
        write(path, src)
        print("kgexec: patched %s" % rel)

    for rel in ("kernel/module/main.c", "kernel/module.c"):
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            continue
        src = read(path)
        if "kg_cred_block_module" in src:
            print("kgexec: %s already patched" % rel)
            break
        if MOD_ANCHOR not in src:
            fail("%s: no anchor for the module hook" % rel)
        if CRED_INCLUDE_LINE not in src:
            src = insert_after(src, MOD_INCLUDE_ANCHOR, CRED_INCLUDE_LINE,
                               "%s include" % rel)
        if src.count(MOD_ANCHOR) != 1:
            fail("%s: module anchor found %d times"
                 % (rel, src.count(MOD_ANCHOR)))
        src = insert_after(src, MOD_ANCHOR, MOD_HOOK, "%s hook" % rel)
        write(path, src)
        print("kgexec: patched %s" % rel)
        break
    else:
        fail("no module loader source found")

    path = os.path.join(root, "fs/open.c")
    src = read(path)
    if "kg_cred_check" not in src:
        if CRED_INCLUDE_LINE not in src:
            src = insert_after(src, PROP_INCLUDE_LINE, CRED_INCLUDE_LINE,
                               "fs/open.c cred include")
        src = insert_before(src, PROP_ANCHOR, CRED_OPEN_HOOK,
                            "fs/open.c cred hook")
        write(path, src)
        print("kgexec: patched fs/open.c (cred)")
    else:
        print("kgexec: fs/open.c already has the cred hook")


def verify(root):
    checks = [
        ("mm/mmap.c", "kg_execmem_block_mmap"),
        ("mm/mprotect.c", "kg_execmem_block_mprotect"),
        ("mm/mmap.c", "#include <linux/kg_execmem.h>"),
        ("mm/mprotect.c", "#include <linux/kg_execmem.h>"),
        ("mm/Makefile", "kg_execmem.o"),
        ("mm/kg_execmem.c", "DEFINE_STATIC_KEY_FALSE(kg_execmem_key)"),
        ("include/linux/kg_execmem.h", "DECLARE_STATIC_KEY_FALSE(kg_execmem_key)"),
        ("fs/open.c", "kg_prop_redirect"),
        ("fs/open.c", "kg_dex_block_open"),
        ("fs/open.c", "#include <linux/kg_execmem.h>"),
        ("fs/open.c", "#include <linux/kg_prop.h>"),
        ("fs/Makefile", "kg_prop.o"),
        ("fs/kg_prop.c", "DEFINE_STATIC_KEY_FALSE(kg_prop_key)"),
        ("include/linux/kg_prop.h", "DECLARE_STATIC_KEY_FALSE(kg_prop_key)"),
        ("kernel/kg_cred.c", "DEFINE_STATIC_KEY_FALSE(kg_cred_key)"),
        ("include/linux/kg_cred.h", "DECLARE_STATIC_KEY_FALSE(kg_cred_key)"),
        ("kernel/Makefile", "kg_cred.o"),
        ("kernel/cred.c", "kg_cred_commit(task, new)"),
        ("kernel/fork.c", "kg_cred_fork(p)"),
        ("kernel/exit.c", "kg_cred_exit(tsk)"),
        ("fs/exec.c", "kg_cred_check()"),
        ("fs/exec.c", "kg_cred_block_exec(bprm->file)"),
        ("fs/open.c", "kg_cred_check()"),
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

    for rel in ("mm/mmap.c", "mm/mprotect.c", "mm/Makefile",
                "fs/open.c", "fs/Makefile", "kernel/cred.c", "kernel/fork.c",
                "kernel/exit.c", "fs/exec.c", "kernel/Makefile"):
        if not os.path.isfile(os.path.join(root, rel)):
            fail("not a kernel tree: %s" % root)

    shutil.copyfile(os.path.join(srcdir, "kg_execmem.c"),
                    os.path.join(root, "mm/kg_execmem.c"))
    os.makedirs(os.path.join(root, "include/linux"), exist_ok=True)
    shutil.copyfile(os.path.join(srcdir, "kg_execmem.h"),
                    os.path.join(root, "include/linux/kg_execmem.h"))
    shutil.copyfile(os.path.join(srcdir, "kg_prop.c"),
                    os.path.join(root, "fs/kg_prop.c"))
    shutil.copyfile(os.path.join(srcdir, "kg_prop.h"),
                    os.path.join(root, "include/linux/kg_prop.h"))

    patch_c(os.path.join(root, "mm/mmap.c"), MMAP_ANCHOR, MMAP_HOOK, "mm/mmap.c")
    patch_c(os.path.join(root, "mm/mprotect.c"), MPROTECT_ANCHOR,
            MPROTECT_HOOK, "mm/mprotect.c")
    patch_makefile(os.path.join(root, "mm/Makefile"))
    patch_c(os.path.join(root, "fs/open.c"), PROP_ANCHOR, PROP_HOOK,
            "fs/open.c", marker="kg_prop",
            inc_anchor=PROP_INCLUDE_ANCHOR, inc_line=PROP_INCLUDE_LINE)
    patch_makefile(os.path.join(root, "fs/Makefile"), PROP_MAKEFILE_LINE,
                   "fs/Makefile")
    patch_dex(os.path.join(root, "fs/open.c"))

    shutil.copyfile(os.path.join(srcdir, "kg_cred.c"),
                    os.path.join(root, "kernel/kg_cred.c"))
    shutil.copyfile(os.path.join(srcdir, "kg_cred.h"),
                    os.path.join(root, "include/linux/kg_cred.h"))
    patch_makefile(os.path.join(root, "kernel/Makefile"), CRED_MAKEFILE_LINE,
                   "kernel/Makefile")
    patch_cred(root)

    verify(root)


main()
