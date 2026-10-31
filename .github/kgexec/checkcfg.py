import gzip
import sys

NEED = (
    "CONFIG_UPROBES=y",
    "CONFIG_UPROBE_EVENTS=y",
    "CONFIG_PROC_MEM_FORCE_PTRACE=y",
    "CONFIG_KPROBES=y",
    "CONFIG_KPROBE_EVENTS=y",
    "CONFIG_BPF_SYSCALL=y",
    "CONFIG_DEBUG_INFO_BTF=y",
    "CONFIG_IKCONFIG_PROC=y",
)

BANNED = (
    "CONFIG_PROC_MEM_ALWAYS_FORCE=y",
    "CONFIG_DEVMEM=y",
    "CONFIG_PROC_KCORE=y",
)


def config_of(path):
    with open(path, "rb") as fh:
        data = fh.read()
    start = data.find(b"IKCFG_ST")
    if start < 0:
        sys.exit("kgexec: no embedded config in %s" % path)
    end = data.find(b"IKCFG_ED", start + 8)
    if end < 0:
        sys.exit("kgexec: embedded config in %s is truncated" % path)
    return gzip.decompress(data[start + 8:end]).decode("utf-8", "replace")


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: checkcfg.py <Image>")
    lines = set(config_of(sys.argv[1]).splitlines())
    missing = [n for n in NEED if n not in lines]
    present = [n for n in BANNED if n in lines]
    if missing:
        sys.stderr.write("kgexec: built kernel misses %s\n"
                         % " ".join(missing))
    if present:
        sys.stderr.write("kgexec: built kernel still carries %s\n"
                         % " ".join(present))
    if missing or present:
        sys.exit(1)
    print("kgexec: built kernel carries every required option")


main()
