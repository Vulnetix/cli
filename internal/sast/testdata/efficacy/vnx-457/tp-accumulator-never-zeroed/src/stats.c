#include <stddef.h>

long sum_samples(const int *samples, size_t n)
{
    long total;
    size_t i;

    for (i = 0; i < n; i++) {
~>        total += samples[i];
    }
    return total;
}
