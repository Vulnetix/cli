#include <stdlib.h>
#include <string.h>

long *grow(long *table, size_t n)
{
    long *t = realloc(table, n * sizeof(long));
    memset(t, 0, n * sizeof(long));
    long *last = t + (n - 1);
    return last;
}

size_t bytes_for(size_t n)
{
    return n * sizeof(long) + sizeof(int);
}
