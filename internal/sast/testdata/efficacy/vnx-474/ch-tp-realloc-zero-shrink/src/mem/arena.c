#include <stdlib.h>

struct arena { char *base; size_t cap; };

void arena_reset(struct arena *a)
{
~>    a->base = realloc(a->base, 0);
    a->cap = 0;
}
