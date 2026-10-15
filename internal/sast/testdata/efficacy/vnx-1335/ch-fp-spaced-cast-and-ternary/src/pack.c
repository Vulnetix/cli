#include <stdint.h>

uint64_t pack(int hi, unsigned lo)
{
    uint64_t wide = (uint64_t) hi << 32;
    return wide | (uint64_t)lo;
}

uint64_t pick(uint64_t value, int upper)
{
    return upper ? value >> 32 : value & 0xffffffffu;
}

uint64_t ll(void)
{
    return 1ULL << 32;
}
