#include <stdint.h>

uint64_t combine(uint32_t seed, const uint8_t *p, int n)
{
    uint32_t h = seed;
    unsigned int carry = 0;
    for (int i = 0; i < n; i++) {
        h = h * 31 + p[i];
    }
~>    carry = h >> 32;
~>    h <<= 32;
~>    return ((uint64_t)carry) | (seed << 32);
}
