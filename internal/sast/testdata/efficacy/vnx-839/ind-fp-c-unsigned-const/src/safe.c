#include <stdlib.h>
#include <stddef.h>

static char *names[16];

int set_u(const char *arg, char *value) {
    size_t idx = strtoul(arg, NULL, 10);
    if (idx >= 16)
        return -1;
    names[idx] = value;
    return 0;
}

int set_c(char *value) {
    int idx = 3;
    if (idx < 16)
        names[idx] = value;
    return 0;
}

int check_only(const char *arg) {
    int limit = atoi(arg);
    if (limit < 100)
        return 1;
    return 0;
}
