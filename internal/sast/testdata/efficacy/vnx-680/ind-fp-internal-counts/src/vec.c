#include <stdlib.h>
#include <string.h>

#define MAX_ITEMS 64

struct vec { int *data; size_t len, cap; };

int vec_grow(struct vec *v)
{
    size_t ncap = v->cap * 2;
    int *nd = realloc(v->data, ncap * sizeof(int));
    if (!nd)
        return -1;
    v->data = nd;
    v->cap = ncap;
    return 0;
}

char *dup_chars(const char *s)
{
    char *t = malloc(strlen(s) * sizeof(char) + 1);
    int *fixed = malloc(MAX_ITEMS * sizeof(int));
    free(fixed);
    return t;
}
