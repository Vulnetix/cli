#include <stddef.h>

int sum_every_other(int *values, size_t n)
{
    int total = 0;
    for (size_t i = 0; i < n; i += 2) {
~>        total += *(values + i * sizeof(int));
    }
    return total;
}

void clear_slot(long *slots, int idx)
{
~>    long *slot = slots + idx * sizeof(long);
    *slot = 0;
}

double last_sample(double *samples, size_t count)
{
~>    return *(samples + (count - 1) * sizeof *samples);
}
