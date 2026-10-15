#include <stdlib.h>

int grow(char **out, size_t *cap) {
    size_t next = *cap * 2;
    char *tmp = realloc(*out, next);
    if (tmp == NULL) {
        return -1;
    }
    *out = tmp;
    *cap = next;
    return 0;
}

void fresh(char **p, size_t n) {
    char *a = realloc(NULL, n);
    *p = a;
}
