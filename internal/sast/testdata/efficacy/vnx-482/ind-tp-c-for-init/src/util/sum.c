#include <stddef.h>

long sum(const int *v, size_t n)
{
    size_t i = 0;
    long total = 0;

~>    for (i == 0; i < n; i++)
        total += v[i];
    return total;
}
