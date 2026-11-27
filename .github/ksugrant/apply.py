#!/usr/bin/env python3
"""Менеджер KernelSU, встроенный в системный раздел, тоже должен крестить.

Ядро ищет менеджера само (track_throne → search_manager) и только в
/data/app. Менеджер, уложенный в образ, оно не видит: is_manager() для
него ложно, поэтому его интерфейс сообщает, что KernelSU не установлен,
и выдавать права он не может.

Правка одна: если в /data/app менеджер не найден, ядро ищет его ещё и в
/system/app. Условия к раскладке ставит само ядро и они не меняются —
файл называется base.apk, каталог называется <пакет>-<суффикс> (имя
пакета ядро берёт до первого дефиса), подпись сверяется по длине
сертификата и его SHA-256.

Выдача root списку пакетов сюда не входит: её делает снаружи штатный
`ksud profile set`, тем же supercall, каким её делает менеджер.
"""
import os
import sys

CANDIDATES = ("KernelSU-Next",)

MGR_ANCHOR = '\t\tsearch_manager("/data/app", 2, &uid_list);\n'
MGR_HOOK = ('\t\tif (!ksu_is_manager_appid_valid()) {\n'
            '\t\t\tpr_info("Searching manager in /system/app...\\n");\n'
            '\t\t\tsearch_manager("/system/app", 2, &uid_list);\n'
            '\t\t}\n')


def fail(msg):
    sys.stderr.write("ksugrant: %s\n" % msg)
    sys.exit(1)


def read(path):
    if not os.path.isfile(path):
        fail("нет файла %s" % path)
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        return fh.read()


def write(path, data):
    with open(path, "w", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write(data)


def main():
    if len(sys.argv) != 2:
        fail("применение: apply.py <каталог сборки ядра>")
    tree = sys.argv[1]

    root = None
    for one in CANDIDATES:
        if os.path.isdir(os.path.join(tree, one, "kernel")):
            root = os.path.join(tree, one, "kernel")
            break
    if root is None:
        fail("дерева KernelSU-Next нет в %s" % tree)

    throne = os.path.join(root, "manager", "throne_tracker.c")
    src = read(throne)
    if 'search_manager("/system/app"' in src:
        print("ksugrant: поиск менеджера в образе уже добавлен")
        return 0
    if src.count(MGR_ANCHOR) != 1:
        fail("якорь поиска менеджера найден %d раз" % src.count(MGR_ANCHOR))
    write(throne, src.replace(MGR_ANCHOR, MGR_ANCHOR + MGR_HOOK, 1))

    print("ksugrant: менеджер ищется и в /system/app")
    return 0


if __name__ == "__main__":
    sys.exit(main())
