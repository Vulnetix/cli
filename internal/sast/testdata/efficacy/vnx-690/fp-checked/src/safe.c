#include <stdlib.h>
#include <string.h>

char *copy_name(const char *name) {
    char *buf = malloc(strlen(name) + 1);
    if (buf == NULL) {
        return NULL;
    }
    strcpy(buf, name);
    return buf;
}

char *copy2(const char *name) {
    char *b = strdup(name);
    if (!b)
        return NULL;
    b[0] = 'x';
    return b;
}

void home(char *dst, size_t n) {
    const char *h = getenv("HOME");
    if (h != NULL)
        strncpy(dst, h, n);
}

void use_env(char *dst) {
    strcpy(dst, getenv("HOME") ? getenv("HOME") : "/");
}
