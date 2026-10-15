#include <stdlib.h>
#include <string.h>

char *dup(const char *s) {
    char *copy = malloc(strlen(s) + 1);
    if (copy == NULL)
        return NULL;
    memcpy(copy, s, strlen(s) + 1);
    return copy;
}

char *dup2(const char *s) {
    size_t n = strlen(s);
    char *p = (char *)malloc(n + 1);
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}
