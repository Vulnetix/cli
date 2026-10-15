#include <stdlib.h>

struct item { int id; };
struct vec { struct item *items; size_t cap; };

int vec_grow(struct vec *v)
{
    v->cap *= 2;
~>    v->items = (struct item *) realloc(v->items, sizeof(*v->items) * v->cap);
    return v->items ? 0 : -1;
}

int table_grow(char **rows, int i, size_t n)
{
~>    rows[i] = realloc(rows[i],
                      n);
    return rows[i] != NULL;
}
