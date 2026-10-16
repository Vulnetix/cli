#include <stdint.h>
#include <stddef.h>

uint32_t mix(uint32_t *words, size_t k)
{
~>    uint32_t *w = words + k * sizeof(uint32_t);
    return *w ^ (*w >> 16);
}
