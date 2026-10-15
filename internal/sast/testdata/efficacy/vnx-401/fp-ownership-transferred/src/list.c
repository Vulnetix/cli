#include <stdlib.h>

char *dup_name(const char *src)
{
    char *copy = strdup(src);
    if (!copy)
        return NULL;
    return copy;
}

int add_entry(struct list *l, const char *name)
{
    struct entry *e = malloc(sizeof(*e));
    if (e == NULL)
        return -1;
    e->name = name;
    list_push(l, e);
    if (l->count > l->limit)
        return 1;
    return 0;
}

int stash(struct ctx *c, size_t n)
{
    void *p = malloc(n);
    c->scratch = p;
    if (n > 4096)
        return -1;
    return 0;
}
