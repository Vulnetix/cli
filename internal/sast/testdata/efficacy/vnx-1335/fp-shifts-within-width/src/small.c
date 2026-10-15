#include <stdint.h>

uint32_t small(uint32_t x, uint64_t big)
{
    uint32_t a = 1u << 31;
    uint32_t b = 1 << 16;
    uint32_t c = x >> 16;
    uint64_t d = big >> 32;
    uint32_t e = 1 << 32 - 1;
    uint32_t f = (uint32_t)(big >> 32);
    return a | b | c | (uint32_t)d | e | f;
}
