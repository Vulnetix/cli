#include <stdlib.h>

size_t pool_span(size_t count)
{
    char *first = malloc(count);
    char *second = (char *)calloc(count, 1);
    if (!first || !second)
        return 0;
~>    size_t span = second - first;
    free(first);
    free(second);
    return span;
}

long pair_distance(void)
{
    int *a = malloc(8 * sizeof(int));
    int *b = malloc(8 * sizeof(int));
~>    long d = (long)(b -
                    a);
    free(a);
    free(b);
    return d;
}
