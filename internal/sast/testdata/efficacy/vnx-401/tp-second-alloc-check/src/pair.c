#include <stdlib.h>

struct pair *pair_new(size_t n)
{
    int *keys = (int *)calloc(n, sizeof(int));
    if (keys == NULL)
        return NULL;
    int *vals = (int *) calloc(n, sizeof(int));
~>    if (vals == NULL) return NULL;
    return pair_wrap(keys, vals, n);
}
