#include "linux/stub.h"

struct user_namespace init_user_ns;
u32 kg_test_uid = 0;
struct task kg_current = { "bench" };
struct filename *kg_last_out = NULL;
struct kg_remap_log kg_remaps[16];
int kg_remap_n = 0;
int kg_open_fail = 0;
long kg_open_size = 128 * 1024;
static struct mm_struct kg_mm;

#define static_cut static
#include "kg_prop_body.c"

static int fails = 0;

static void chk(const char *what, int ok) {
    printf("%-52s %s\n", what, ok ? "ок" : "СБОЙ");
    if (!ok) fails++;
}

static int add(unsigned key, const char *t, const char *r) {
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "add %u %s %s", key, t, r);
    return kg_prop_proc_write(NULL, cmd, strlen(cmd), NULL);
}

static const char *redir(u32 uid, const char *path) {
    struct filename in;
    in.name = path;
    kg_test_uid = uid;
    kg_last_out = NULL;
    struct filename *out = kg_prop_redirect(&in);
    return out ? out->name : NULL;
}

/* -- подмена унаследованного отображения -- */
static struct file g_files[8];
static struct vm_area_struct g_vmas[8];

static void map(int i, const char *path, unsigned long addr, unsigned long len)
{
    g_files[i].f_path.name = path;
    g_files[i].size = 128 * 1024;
    g_vmas[i].vm_start = addr;
    g_vmas[i].vm_end = addr + len;
    g_vmas[i].vm_file = &g_files[i];
}

static void remap_case(u32 uid, int n)
{
    kg_mm.v = g_vmas;
    kg_mm.n = n;
    kg_current.mm = &kg_mm;
    kg_test_uid = uid;
    kg_remap_n = 0;
    kg_prop_cred_changed();
}

static void bench_remap(void)
{
    const unsigned long L = 128 * 1024;

    kg_prop_proc_write(NULL, "clear", 5, NULL);
    add(10324, "/dev/__properties__/u:object_r:build_prop:s0",
        "/dev/envspoof/p10324/u:object_r:build_prop:s0");
    add(10324, "/dev/__properties__/u:object_r:radio_prop:s0",
        "/dev/envspoof/p10324/u:object_r:radio_prop:s0");

    map(0, "/dev/__properties__/property_info", 0x1000, L);
    map(1, "/dev/__properties__/u:object_r:build_prop:s0", 0x40000, L);
    map(2, "/dev/__properties__/u:object_r:radio_prop:s0", 0x80000, L);
    map(3, "/dev/__properties__/u:object_r:other_prop:s0", 0xc0000, L);
    map(4, "/apex/com.android.runtime/lib64/bionic/libc.so", 0x200000, L);

    remap_case(10324, 5);
    chk("подменены только два отображения с правилом", kg_remap_n == 2);
    chk("первое взято из каталога этого uid",
        kg_remap_n > 0 && strcmp(kg_remaps[0].src,
            "/dev/envspoof/p10324/u:object_r:build_prop:s0") == 0);
    chk("адрес и длина сохранены",
        kg_remap_n > 0 && kg_remaps[0].addr == 0x40000 && kg_remaps[0].len == L);
    chk("второе отображение тоже подменено",
        kg_remap_n > 1 && strcmp(kg_remaps[1].src,
            "/dev/envspoof/p10324/u:object_r:radio_prop:s0") == 0);

    remap_case(10999, 5);
    chk("чужому uid не подменяется ничего", kg_remap_n == 0);

    remap_case(0, 5);
    chk("системному uid не подменяется ничего", kg_remap_n == 0);

    kg_open_fail = 1;
    remap_case(10324, 5);
    chk("недоступная копия пропускается", kg_remap_n == 0);
    kg_open_fail = 0;

    kg_open_size = 4096;
    remap_case(10324, 5);
    chk("копия короче отображения пропускается", kg_remap_n == 0);
    kg_open_size = 128 * 1024;

    kg_current.mm = NULL;
    kg_test_uid = 10324;
    kg_remap_n = 0;
    kg_prop_cred_changed();
    chk("процесс без mm не трогается", kg_remap_n == 0);
    kg_current.mm = &kg_mm;
}

int main(void) {
    char cmd[64];

    chk("add точного пути принят", add(10091, "/proc/version", "/dev/envspoof/10091/version") > 0);
    chk("точный путь перенаправлен",
        redir(10091, "/proc/version") != NULL
        && strcmp(redir(10091, "/proc/version"), "/dev/envspoof/10091/version") == 0);
    chk("чужой uid не трогается", redir(10092, "/proc/version") == NULL);
    chk("другой путь не трогается", redir(10091, "/proc/cpuinfo") == NULL);

    chk("add каталога принят",
        add(10091, "/dev/__properties__/", "/dev/envspoof/10091/props/") > 0);
    const char *r = redir(10091, "/dev/__properties__/u:object_r:default_prop:s0");
    chk("файл в каталоге перенаправлен",
        r != NULL && strcmp(r, "/dev/envspoof/10091/props/u:object_r:default_prop:s0") == 0);
    r = redir(10091, "/dev/__properties__/property_info");
    chk("второй файл того же каталога",
        r != NULL && strcmp(r, "/dev/envspoof/10091/props/property_info") == 0);
    chk("сам каталог без хвоста не ловится",
        redir(10091, "/dev/__properties__") == NULL);
    chk("похожий каталог не ловится",
        redir(10091, "/dev/__properties__x/f") == NULL);

    chk("каталог без '/' в замене отвергнут",
        add(10093, "/proc/x/", "/dev/y") == -EINVAL);
    chk("замена без '/' в цели отвергнута",
        add(10093, "/proc/x", "/dev/y/") == -EINVAL);

    chk("appid действует во всех профилях",
        add(10500, "/proc/cpuinfo", "/dev/envspoof/all/cpuinfo") > 0);
    chk("профиль 0 видит appid-запись",
        redir(10500, "/proc/cpuinfo") != NULL);
    chk("профиль 11 видит appid-запись",
        redir(1110500, "/proc/cpuinfo") != NULL);

    chk("uid перекрывает appid",
        add(1110500, "/proc/cpuinfo", "/dev/envspoof/11/cpuinfo") > 0);
    r = redir(1110500, "/proc/cpuinfo");
    chk("для профиля 11 победила запись uid",
        r != NULL && strcmp(r, "/dev/envspoof/11/cpuinfo") == 0);
    r = redir(10500, "/proc/cpuinfo");
    chk("для профиля 0 осталась запись appid",
        r != NULL && strcmp(r, "/dev/envspoof/all/cpuinfo") == 0);

    chk("системный uid отвергнут", add(1000, "/proc/version", "/dev/x") == -ERANGE);
    chk("номер профиля сверх предела отвергнут",
        add(100010091, "/proc/version", "/dev/x") == -ERANGE);
    chk("относительный путь отвергнут", add(10094, "proc/version", "/dev/x") == -EINVAL);
    chk("выход вверх отвергнут", add(10094, "/proc/../etc/x", "/dev/x") == -EINVAL);

    char longp[300];
    memset(longp, 'a', sizeof(longp) - 1);
    longp[0] = '/';
    longp[sizeof(longp) - 1] = '\0';
    chk("слишком длинный путь отвергнут", add(10095, longp, "/dev/x") == -EINVAL);

    int added = 0;
    for (int i = 0; i < 300; i++) {
        char t[64], d[64];
        snprintf(t, sizeof(t), "/proc/fill%d", i);
        snprintf(d, sizeof(d), "/dev/fill%d", i);
        if (add(10096, t, d) > 0) added++;
    }
    chk("таблица не переполняется", added <= 192 && added > 100);

    snprintf(cmd, sizeof(cmd), "clear");
    kg_prop_proc_write(NULL, cmd, strlen(cmd), NULL);
    chk("после clear ничего не ловится", redir(10091, "/proc/version") == NULL);

    bench_remap();

    if (fails == 0) printf("KGPROP-OK\n");
    return fails == 0 ? 0 : 1;
}
