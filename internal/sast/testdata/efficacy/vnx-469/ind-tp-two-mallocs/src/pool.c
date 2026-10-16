#include <stdlib.h>

size_t pool_gap(size_t count)
{
    char *first = malloc(count);
    char *second = malloc(count);
~>    size_t span = second - first;
    free(first);
    free(second);
    return span;
}
