#!/usr/bin/env python3
"""Root по сборке ядра: список пакетов внутри ядра, а не в файле списка.

KernelSU выдаёт полный root любому uid, который пропускает одна калитка
__ksu_is_allow_uid(): записи в списке при этом не требуется — без неё
ksu_get_root_profile() отдаёт default_root_profile (uid 0, полный набор
capabilities, домен u:r:su:s0). Сам список ведут менеджер и ksud, и он
перезагружается из /data/adb/ksu/.allowlist на старте zygote, перекрывая
всё, что в него записали со стороны.

Поэтому разрешение ставится в калитку, а не в список. Отображение
«пакет → uid» берётся из того же разбора /data/system/packages.list,
которым ядро ищет менеджера (track_throne); pkg_observer повторяет этот
разбор при каждом изменении файла, так что uid остаются свежими после
установки и удаления приложений.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CANDIDATES = ("KernelSU-Next",)

GATE_ANCHOR = ("\tif (unlikely(is_uid_manager(uid))) {\n"
               "\t\t// manager is always allowed!\n"
               "\t\treturn true;\n"
               "\t}\n")
GATE_HOOK = ("\n"
             "\tif (ksu_builtin_allowed(uid)) {\n"
             "\t\t// разрешено сборкой ядра: списка для этого не нужно\n"
             "\t\treturn true;\n"
             "\t}\n")

HEAD_ANCHOR = "bool __ksu_is_allow_uid(uid_t uid)\n{\n"

DECL = """
/* Разрешено сборкой ядра: список пакетов и их appid. */
bool ksu_builtin_allowed(uid_t uid);
void ksu_builtin_begin(void);
void ksu_builtin_note(const char *package, uid_t uid);
void ksu_builtin_commit(void);
"""

LIST_ANCHOR = "\tINIT_LIST_HEAD(&uid_list);\n"
LIST_HOOK = "\tksu_builtin_begin();\n"

NOTE_ANCHOR = "\t\tstrscpy(data->package, package, sizeof(data->package));\n"
NOTE_HOOK = "\t\tksu_builtin_note(data->package, res);\n"

COMMIT_ANCHOR = "\t// now update uid list\n"
COMMIT_HOOK = "\tksu_builtin_commit();\n\n"

# Менеджер ядро ищет только в /data/app. Встроенный в образ оно не видит,
# а увидев — ведёт себя как с обычным: всегда пропускает его в root, и
# менеджер сам раскладывает настоящий ksud, от которого зависят события
# загрузки (монтирование модулей, подъём ksu_boot_completed). Условия к
# раскладке ставит само ядро: файл называется base.apk, а имя пакета оно
# берёт из имени каталога до первого дефиса (get_pkg_from_apk_dir_path),
# то есть каталог должен быть <пакет>-<что угодно>.
MGR_ANCHOR = '\t\tsearch_manager("/data/app", 2, &uid_list);\n'
MGR_HOOK = ('\t\tif (!ksu_is_manager_appid_valid()) {\n'
            '\t\t\tpr_info("Searching manager in /system/app...\\n");\n'
            '\t\t\tsearch_manager("/system/app", 2, &uid_list);\n'
            '\t\t}\n')

BOOT_ANCHOR = "    ksu_observer_init();\n"
BOOT_HOOK = ("    // Разбор packages.list: он заполняет appid пакетов,\n"
             "    // разрешённых сборкой. Чистка списка внутри требует\n"
             "    // поднятого ksu_boot_completed и здесь не выполняется.\n"
             "    track_throne(true);\n")


def body(packages):
    rows = "".join('\t"%s",\n' % one for one in packages)
    return '''
/* Пакеты, которым root положен самой сборкой ядра.
 *
 * Разрешение здесь, а не в списке, который ведут менеджер и ksud:
 * список перезагружается из /data/adb/ksu/.allowlist на старте zygote и
 * перекрывает всё, что записано со стороны, а чистка списка требует
 * настоящего ksud. Калитку перекрыть нечем.
 *
 * Записи в списке для root не нужно: без неё ksu_get_root_profile()
 * отдаёт default_root_profile — uid 0, полный набор capabilities, домен
 * u:r:su:s0.
 */
static const char *const ksu_builtin_packages[] = {
%s};

#define KSU_BUILTIN_COUNT ARRAY_SIZE(ksu_builtin_packages)

/* appid (uid %% PER_USER_RANGE) каждого пакета, 0 — пакета в системе
 * нет. Живой набор читает калитка, собираемый заполняет разбор
 * packages.list; набор публикуется целиком, поэтому разрешение не
 * пропадает ни на один разбор. Разбор идёт под throne_tracker_mutex,
 * чтение в калитке без блокировки: устаревшее чтение даёт лишь отказ до
 * следующего разбора.
 */
static u32 ksu_builtin_live[KSU_BUILTIN_COUNT];
static u32 ksu_builtin_draft[KSU_BUILTIN_COUNT];

void ksu_builtin_begin(void)
{
	size_t i;

	for (i = 0; i < KSU_BUILTIN_COUNT; i++)
		ksu_builtin_draft[i] = 0;
}

void ksu_builtin_note(const char *package, uid_t uid)
{
	size_t i;

	for (i = 0; i < KSU_BUILTIN_COUNT; i++) {
		if (!strcmp(package, ksu_builtin_packages[i])) {
			ksu_builtin_draft[i] = uid %% PER_USER_RANGE;
			return;
		}
	}
}

void ksu_builtin_commit(void)
{
	size_t i;

	for (i = 0; i < KSU_BUILTIN_COUNT; i++) {
		if (READ_ONCE(ksu_builtin_live[i]) != ksu_builtin_draft[i]) {
			pr_info("builtin su: %%s appid %%u\\n",
				ksu_builtin_packages[i], ksu_builtin_draft[i]);
		}
		WRITE_ONCE(ksu_builtin_live[i], ksu_builtin_draft[i]);
	}
}

bool ksu_builtin_allowed(uid_t uid)
{
	uid_t appid = uid %% PER_USER_RANGE;
	size_t i;

	if (!appid)
		return false;

	for (i = 0; i < KSU_BUILTIN_COUNT; i++) {
		if (appid == READ_ONCE(ksu_builtin_live[i]))
			return true;
	}

	return false;
}

''' % rows


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


def once(src, anchor, what):
    if src.count(anchor) != 1:
        fail("якорь %s найден %d раз" % (what, src.count(anchor)))


def after(src, anchor, block, what):
    once(src, anchor, what)
    return src.replace(anchor, anchor + block, 1)


def before(src, anchor, block, what):
    once(src, anchor, what)
    return src.replace(anchor, block + anchor, 1)


def packages():
    out = []
    for line in read(os.path.join(HERE, "packages.txt")).splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        if len(line) > 255 or any(c in line for c in ' \t"\\'):
            fail("негодное имя пакета: %r" % line)
        out.append(line)
    if not out:
        fail("список пакетов пуст")
    return out


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

    allow = os.path.join(root, "policy", "allowlist.c")
    head = os.path.join(root, "policy", "allowlist.h")
    throne = os.path.join(root, "manager", "throne_tracker.c")
    boot = os.path.join(root, "runtime", "boot_event.c")

    src = read(allow)
    if "ksu_builtin_allowed" in src:
        print("ksugrant: калитка уже правлена")
        return 0

    names = packages()
    src = before(src, HEAD_ANCHOR, body(names), "тело списка")
    src = after(src, GATE_ANCHOR, GATE_HOOK, "калитка")
    write(allow, src)

    src = read(head)
    if "ksu_builtin_allowed" not in src:
        mark = "void ksu_load_allow_list(void);"
        once(src, mark, "объявления списка")
        src = src.replace(mark, mark + DECL, 1)
        write(head, src)

    src = read(throne)
    src = after(src, MGR_ANCHOR, MGR_HOOK, "поиск менеджера в образе")
    src = after(src, LIST_ANCHOR, LIST_HOOK, "начало разбора")
    src = after(src, NOTE_ANCHOR, NOTE_HOOK, "запись пакета")
    src = before(src, COMMIT_ANCHOR, COMMIT_HOOK, "публикация набора")
    write(throne, src)

    src = read(boot)
    src = after(src, BOOT_ANCHOR, BOOT_HOOK, "разбор на post-fs-data")
    write(boot, src)

    print("ksugrant: root по сборке ядра для %d пакетов: %s"
          % (len(names), ", ".join(names)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
