#include <stdlib.h>
#include <string.h>

int vec_push(struct vec *v, int x)
{
    int *tmp = realloc(v->data, (v->cap * 2) * sizeof(int));
    if (tmp == NULL) {
        return -1;
    }
    v->data = tmp;
    v->data[v->len++] = x;
    return 0;
}

char *append(char *buf, size_t len, const char *s, size_t n)
{
    char *tmp = realloc(buf, len + n + 1);
    if (tmp == NULL) {
        free(buf);
        return NULL;
    }
    buf = tmp;
    memcpy(buf + len, s, n + 1);
    return buf;
}

void grow_inplace(char *p, size_t n)
{
    p = realloc(p, n);
    p[0] = 0;
}
