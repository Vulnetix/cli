#include <stdlib.h>

struct vec { int *items; size_t len; };

void vec_clear(struct vec *v)
{
~>    v->items = realloc(v->items, 0);
    v->len = 0;
}

void *shrink(void *p)
{
~>    return realloc( p , 0 );
}
