#include <stdint.h>

uint64_t ok(void)
{
    uint64_t a = 1ULL << 40;
    uint64_t b = 1ull << 63;
    uint64_t c = UINT64_C(1) << 40;
    uint64_t d = (uint64_t)1 << 63;
    uint64_t e = 0x1LL << 33;
    uint64_t f = 1L << 40;
    return a | b | c | d | e | f;
}
