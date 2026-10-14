#include <stdlib.h>
#include <string.h>

struct list { char **items; size_t len; size_t cap; };

int list_grow(struct list *l)
{
    size_t cap = l->cap ? l->cap * 2 : 8;
    char **items = realloc(l->items, cap * sizeof(char *));

    if (items == NULL)
        return -1;
    l->items = items;
    l->cap = cap;
    return 0;
}

char *dup_with_nul(const char *s)
{
    size_t len = strlen(s);
    char *copy = malloc(len + 1);
    memcpy(copy, s, len + 1);
    return copy;
}
