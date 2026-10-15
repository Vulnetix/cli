#include <stdlib.h>

int vec_push(struct vec *v, int x)
{
    int *grown = realloc(v->items, (v->len + 1) * sizeof(int));
    if (grown == NULL) {
        log_error("out of memory with %zu items", v->len);
        free(v->items);
        v->items = NULL;
        return -1;
    }
    v->items = grown;
    v->items[v->len++] = x;
    return 0;
}

char *append(char *buf, size_t len)
{
    char *tmp = realloc(buf, len * 2);
    if (tmp == NULL) { free(buf); return NULL; }
    buf = tmp;
    buf[len] = 0;
    return buf;
}

char *shift(char *base, char *cur, size_t n)
{
    char *nb = realloc(base, n);
    if (!nb)
        return NULL;
    size_t off = cur - base;
    return nb + off;
}
