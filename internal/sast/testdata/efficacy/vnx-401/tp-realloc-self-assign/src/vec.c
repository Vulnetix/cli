#include <stdlib.h>

int vec_grow(struct vec *v, size_t cap)
{
~>    v->items = realloc(v->items, cap * sizeof(*v->items));
    if (!v->items)
        return -1;
    v->cap = cap;
    return 0;
}

char *append(char *line, size_t maxlen)
{
~>    line = realloc( line, maxlen );
    return line;
}
