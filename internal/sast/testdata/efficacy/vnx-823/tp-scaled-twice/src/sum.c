#include <stdint.h>

long sum_values(void)
{
    int values[16];
    long total = 0;
~>    for (int *p = values; p < values + sizeof(values); p++)
        total += *p;
    return total;
}

void clear_tail(uint32_t *words, unsigned n)
{
~>    uint32_t *tail = words + sizeof(uint32_t) * n;
    *tail = 0;
}
