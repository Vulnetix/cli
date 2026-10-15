#include <stdint.h>

uint64_t high_bit_mask(void)
{
~>    uint64_t mask = 1 << 40;
    return mask;
}

unsigned int wide(void)
{
~>    unsigned int x = 1u << 40;
    return x;
}
