#include "linux/stub.h"

struct user_namespace init_user_ns;
u32 kg_test_uid = 0;
struct task kg_current = { "bench" };
struct filename *kg_last_out = NULL;

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

    if (fails == 0) printf("KGPROP-OK\n");
    return fails == 0 ? 0 : 1;
}
