#include <string.h>

static char saved[64];

void save(const char *in, char *out, size_t n) {
    char tmp[64];
    char *cursor = tmp;
    memcpy(tmp, saved, sizeof(saved));
    memmove(saved, tmp, sizeof tmp);
    snprintf(cursor, sizeof(tmp), "%s", in);
    strncpy(out, in, sizeof(saved) - 1);
    fgets(tmp, sizeof(tmp) - 1, stdin);
    memset(tmp, 0, n);
}
