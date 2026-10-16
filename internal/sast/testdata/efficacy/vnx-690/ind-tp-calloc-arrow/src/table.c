#include <stdlib.h>

struct table { int size; int *slots; };

struct table *table_new(int n)
{
    struct table *t = calloc(1, sizeof(*t));
~>    t->size = n;
    t->slots = calloc(n, sizeof(int));
    return t;
}
