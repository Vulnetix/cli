#include <stdlib.h>
#include <string.h>

int vec_push(struct vec *v, int x)
{
    int *grown = realloc(v->items, (v->len + 1) * sizeof(int));
    if (grown == NULL)
        return -1;
~>  v->items[v->len] = x;
    v->items = grown;
    v->len++;
    return 0;
}

char *append(char *buf, size_t len, const char *s)
{
    size_t n = strlen(s);
    char *tmp = (char *)realloc(buf, len + n + 1);
    if (!tmp) {
        free(buf);
        return NULL;
    }
~>  memcpy(buf + len, s, n + 1);
    return tmp;
}
