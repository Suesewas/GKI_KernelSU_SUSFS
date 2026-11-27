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
void ksu_builtin_refresh(void);
"""

# Разбор packages.list свой, а не врезка в чужой цикл: тот от ревизии к
# ревизии переезжает, выходит молча по нескольким путям и ничего о себе
# не сообщает. Свой зовётся оттуда же, где ядро уже держит свои
# полномочия и где спать не запрещено.
REFRESH_ANCHOR = "\t// now update uid list\n"
REFRESH_HOOK = "\tksu_builtin_refresh();\n\n"

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

#define KSU_BUILTIN_LIST "/data/system/packages.list"
#define KSU_BUILTIN_BUF 4096

/* Запись профиля — то же, что делает менеджер нажатием переключателя.
 *
 * Одного «да» в калитке мало: профиль ищут и те места, которые решают,
 * что приложение увидит. ksu_uid_should_umount() без записи берёт
 * default_non_root_profile и отмонтирует приложению модули, то есть оно
 * не найдёт ни /data/adb/modules, ни своего модуля, и решит, что root
 * нет, не дойдя до вызова su. Поэтому разрешённым пакетам ставится
 * настоящая запись: allow_su, профиль по умолчанию (uid 0, полные
 * capabilities, домен u:r:su:s0).
 *
 * profile_valid() сверяет selinux_domain даже при use_default, поэтому
 * тело заполняется копией default_root_profile, а не нулями.
 */
static void ksu_builtin_set_profile(const char *pkg, uid_t uid)
{
	struct app_profile *profile;

	profile = kzalloc(sizeof(*profile), GFP_KERNEL);
	if (!profile)
		return;

	profile->version = KSU_APP_PROFILE_VER;
	strscpy(profile->key, pkg, sizeof(profile->key));
	profile->curr_uid = uid;
	profile->allow_su = true;
	profile->rp_config.use_default = true;
	memcpy(&profile->rp_config.profile, &default_root_profile,
	       sizeof(profile->rp_config.profile));

	if (ksu_set_app_profile(profile))
		pr_err("builtin su: профиль не лёг: %%s uid %%u\\n", pkg, uid);
	else
		pr_info("builtin su: профиль записан: %%s uid %%u\\n", pkg, uid);

	kfree(profile);
}

/* Пакет и его uid — первые два поля строки packages.list. Отчёт в
 * журнал безусловный, включая «не совпало ничего»: иначе пустой список
 * не отличить от неразобранного файла. */
void ksu_builtin_refresh(void)
{
	struct file *fp;
	char *buf;
	loff_t pos = 0;
	size_t have = 0, lines = 0, found = 0, wrote = 0;
	size_t i;

	for (i = 0; i < KSU_BUILTIN_COUNT; i++)
		ksu_builtin_draft[i] = 0;

	fp = filp_open(KSU_BUILTIN_LIST, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_info("builtin su: %%s не открылся: %%ld\\n", KSU_BUILTIN_LIST,
			PTR_ERR(fp));
		return;
	}

	buf = kmalloc(KSU_BUILTIN_BUF, GFP_KERNEL);
	if (!buf) {
		filp_close(fp, NULL);
		return;
	}

	for (;;) {
		char *p, *nl;
		ssize_t n = kernel_read(fp, buf + have,
				       KSU_BUILTIN_BUF - 1 - have, &pos);

		if (n <= 0)
			break;
		have += (size_t)n;
		buf[have] = '\\0';

		p = buf;
		while ((nl = strchr(p, '\\n')) != NULL) {
			char *sp, *uidp, *sp2;
			u32 uid;

			*nl = '\\0';
			lines++;
			sp = strchr(p, ' ');
			if (sp) {
				*sp = '\\0';
				uidp = sp + 1;
				sp2 = strchr(uidp, ' ');
				if (sp2)
					*sp2 = '\\0';
				if (!kstrtou32(uidp, 10, &uid)) {
					for (i = 0; i < KSU_BUILTIN_COUNT; i++) {
						if (strcmp(p, ksu_builtin_packages[i]))
							continue;
						ksu_builtin_draft[i] =
							uid %% PER_USER_RANGE;
						found++;
						break;
					}
				}
			}
			p = nl + 1;
		}

		have -= (size_t)(p - buf);
		memmove(buf, p, have);
		/* строка длиннее буфера: отбрасываем остаток, а не зависаем */
		if (have >= KSU_BUILTIN_BUF - 1)
			have = 0;
	}

	kfree(buf);
	filp_close(fp, NULL);

	for (i = 0; i < KSU_BUILTIN_COUNT; i++) {
		u32 was = READ_ONCE(ksu_builtin_live[i]);
		u32 now = ksu_builtin_draft[i];

		WRITE_ONCE(ksu_builtin_live[i], now);
		if (!now)
			continue;
		pr_info("builtin su: %%s appid %%u\\n",
			ksu_builtin_packages[i], now);
		/* профиль ставится при первом появлении пакета и при смене
		 * uid: разбор повторяется на каждое изменение packages.list,
		 * а переписывать запись на каждый разбор незачем. */
		if (now != was) {
			ksu_builtin_set_profile(ksu_builtin_packages[i], now);
			wrote++;
		}
	}
	if (wrote)
		ksu_persistent_allow_list();
	pr_info("builtin su: строк %%zu, разрешено %%zu из %%zu, профилей %%zu\\n",
		lines, found, (size_t)KSU_BUILTIN_COUNT, wrote);
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
    src = before(src, REFRESH_ANCHOR, REFRESH_HOOK, "свой разбор списка")
    write(throne, src)

    src = read(boot)
    src = after(src, BOOT_ANCHOR, BOOT_HOOK, "разбор на post-fs-data")
    write(boot, src)

    print("ksugrant: root по сборке ядра для %d пакетов: %s"
          % (len(names), ", ".join(names)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
