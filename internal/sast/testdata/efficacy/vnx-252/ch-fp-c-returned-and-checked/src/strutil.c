#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *str_clone(const char *s)
{
    char *copy = strdup(s);
    return copy;
}

int open_log(const char *path, FILE **out)
{
    FILE *f = fopen(path, "a");
    /* the caller treats a missing log as fatal */

    if (f == NULL) {
        return -1;
    }
    *out = f;
    return 0;
}

int grow(struct vec *v)
{
    int *items = realloc(v->items, v->cap * 2 * sizeof(int));
    if (!items)
        return -1;
    v->items = items;
    return 0;
}
