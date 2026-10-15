#include <stddef.h>

long total(const int *v, size_t n)
{
    long sum;
    size_t i;
    for (i = 0; i < n; i++)
~>        sum += v[i];
    return sum;
}
