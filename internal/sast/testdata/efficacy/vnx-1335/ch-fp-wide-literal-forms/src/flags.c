#include <stdint.h>

#define BIT64(n) (UINT64_C(1) << (n))

uint64_t flags(void)
{
    uint64_t a = 1ULL << 40;
    uint64_t b = UINT64_C(1) << 63;
    uint64_t c = (uint64_t)1 << 32;
    uint64_t d = 1ull << 33;
    return a | b | c | d;
}
