#include <stdint.h>

uint32_t mix(uint32_t h)
{
    uint32_t k = h * 0x9e3779b1u;
~>    k <<= 33;
    return k ^ h;
}
