#include <stdint.h>

void split(uint64_t v, uint32_t *hi, uint32_t *lo)
{
~>    uint32_t top = (uint32_t)v >> 32;
    *hi = top;
    *lo = (uint32_t)v;
}

int widen(int x)
{
~>    return (int) x << 32;
}
