#include <stdlib.h>
#include <string.h>

struct buf {
    char *data;
    size_t cap;
};

void buf_reset(struct buf *b)
{
    free(b->data);
    b->data = NULL;
    b->cap = 0;
    if (b->data == NULL)
        b->cap = 16;
}

char *grow(char *p, size_t n)
{
    free(p);
    p = malloc(n);
    memset(p, 0, n);
    return p;
}

void swap_in(char **slot, char *fresh)
{
    free(*slot);
    *slot = fresh;
}

void refill(char *p)
{
    free(p); p = NULL;
    if (!p)
        p = strdup("x");
}

void reload(char *name)
{
    free(name);
    load_name(&name);
    puts(name);
}
