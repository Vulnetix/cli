#include <stdint.h>
#include "cpu.h"

uint32_t hash_block(const uint8_t *p, size_t n)
{
    cpu_relax();
    return crc32_hw(p, n);
}
