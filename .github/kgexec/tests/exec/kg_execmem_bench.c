#include "linux/stub.h"

struct user_namespace init_user_ns;
u32 kg_test_uid = 0;
struct task kg_current = { "bench" };
int kg_cred_on = 0;
u32 kg_cred_base = 0;

char *kg_d_path_path(struct path *p, char *buf, int n)
{
	struct file *f = (struct file *)((char *)p - offsetof(struct file, f_path));

	strncpy(buf, f->path ? f->path : "/", (size_t)n - 1);
	buf[n - 1] = '\0';

	return buf;
}

long kg_kernel_read(struct file *f, void *buf, size_t n, loff_t *pos)
{
	long have = f->body ? f->body_n : 0;
	long at = pos ? (long)*pos : 0;
	long take;

	if (at >= have)
		return 0;
	take = have - at;
	if ((long)n < take)
		take = (long)n;
	memcpy(buf, f->body + at, (size_t)take);
	if (pos)
		*pos = at + take;

	return take;
}

#include "kg_execmem_body.c"

static int fails;

static void chk(const char *what, int ok)
{
	printf("%-56s %s\n", what, ok ? "ок" : "СБОЙ");
	if (!ok)
		fails++;
}

static int cmd(const char *s)
{
	char buf[256];
	ssize_t r;

	snprintf(buf, sizeof(buf), "%s", s);
	r = kg_proc_write(NULL, buf, strlen(buf), NULL);

	return r < 0 ? (int)r : 0;
}

static struct file *mkfile(const char *path, const char *body, long n)
{
	static struct file files[8];
	static int used;
	struct file *f = &files[used++ % 8];

	memset(f, 0, sizeof(*f));
	f->f_mode = FMODE_READ;
	f->path = path;
	f->body = body;
	f->body_n = n;
	f->ino.i_mode = S_IFREG;
	f->sb.s_magic = 0x58465342;
	f->ino.i_sb = &f->sb;
	f->ino.i_size = n;
	f->inode = &f->ino;
	f->f_path.dentry = &f->dent;

	return f;
}

static const char WEBAPK[] = "/product/app/Vanadium/Vanadium.apk";
static const char OTHER[] = "/product/app/Other/Other.apk";
static const char DEXZIP[] = "/data/local/tmp/payload.jar";

static char report[KG_OUT_MAX];

static void grab(void)
{
	loff_t off = 0;

	memset(report, 0, sizeof(report));
	kg_proc_read(NULL, report, sizeof(report) - 1, &off);
}

int main(void)
{
	struct file *web, *other, *jar;
	char dex[64];

	kg_test_uid = 10281;
	web = mkfile(WEBAPK, "PK\x03\x04", 4);
	other = mkfile(OTHER, "PK\x03\x04", 4);

	/* -- путь движка ставится и виден в отчёте -- */
	chk("путь движка принимается", cmd("web /product/app/Vanadium/") == 0);
	chk("путь без корня отвергается", cmd("web product/app/X") == -EINVAL);
	grab();
	chk("путь движка виден в отчёте",
	    strstr(report, "web 1\n") && strstr(report, "webpath /product/app/Vanadium/"));
	chk("признак ядра поднят до нового",
	    strstr(report, "abi 10\n") != NULL);

	/* -- без признака движок открывается -- */
	chk("без признака движок отдаётся", cmd("add 10281 2") == 0);
	chk("открытие движка разрешено", !kg_dex_block_open(web));

	/* -- с признаком движок не отдаётся -- */
	chk("признак движка принимается", cmd("add 10281 64") == 0);
	chk("открытие движка отвергнуто", kg_dex_block_open(web));
	chk("чужой файл в том же каталоге не трогается", !kg_dex_block_open(other));

	grab();
	chk("отказ отмечен причиной движка",
	    strstr(report, "seen 10281 64") != NULL);

	/* -- соседние приложения не задеты -- */
	kg_test_uid = 10282;
	chk("другому приложению движок отдаётся", !kg_dex_block_open(web));
	kg_test_uid = 10281;

	/* -- признак запрета принесённого кода работает как прежде -- */
	memcpy(dex, "dex\n035", 7);
	jar = mkfile(DEXZIP, dex, 7);
	chk("признак кода принимается", cmd("add 10281 16") == 0);
	chk("принесённый код по-прежнему отвергается", kg_dex_block_open(jar));
	chk("движок при этом признаке отдаётся", !kg_dex_block_open(web));

	/* -- оба признака вместе -- */
	chk("оба признака вместе принимаются", cmd("add 10281 80") == 0);
	chk("движок отвергнут", kg_dex_block_open(web));
	chk("код отвергнут", kg_dex_block_open(jar));

	/* -- наблюдение вместо отказа для обособленного процесса -- */
	kg_test_uid = 99010;
	chk("умолчание с движком принимается", cmd("default 64") == 0);
	chk("обособленному процессу только отметка", !kg_dex_block_open(web));
	kg_test_uid = 10281;
	chk("умолчание снимается", cmd("default 0") == 0);

	/* -- умолчание действует на приложение без записи -- */
	kg_test_uid = 10283;
	chk("умолчание с движком ставится", cmd("default 64") == 0);
	chk("приложение без записи берёт умолчание", kg_dex_block_open(web));
	chk("умолчание снимается обратно", cmd("default 0") == 0);
	kg_test_uid = 10281;

	/* -- список путей ограничен и очищается -- */
	chk("второй путь принимается", cmd("web /apex/com.android.webview/") == 0);
	chk("третий путь принимается", cmd("web /data/app/~~w/") == 0);
	chk("четвёртый путь принимается", cmd("web /system/app/W/") == 0);
	chk("пятый путь не влезает", cmd("web /system/app/X/") == -ENOSPC);
	chk("список очищается", cmd("web clear") == 0);
	grab();
	chk("после очистки путей нет", strstr(report, "web 0\n") != NULL);
	chk("без путей движок отдаётся", !kg_dex_block_open(web));

	/* -- пломба не даёт менять пути -- */
	chk("путь ставится до пломбы", cmd("web /product/app/Vanadium/") == 0);
	chk("пломба ставится", cmd("seal") == 0);
	chk("после пломбы путь не поменять",
	    cmd("web /product/app/Other/") == -EPERM);
	chk("после пломбы запрет остаётся в силе", kg_dex_block_open(web));

	printf("\nпроверок: %d, сбоев: %d\n", 33, fails);
	puts(fails ? "KGEXEC-FAIL" : "KGEXEC-OK");

	return fails ? 1 : 0;
}
