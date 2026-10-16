#include <stdint.h>
uint64_t masks(uint32_t hi, uint32_t lo)
{
    uint64_t a = 1ULL << 40;
    uint64_t b = UINT64_C(1) << 40;
    uint64_t c = (uint64_t)1 << 63;
    return ((uint64_t)hi << 32) | lo | a | b | c;
}
