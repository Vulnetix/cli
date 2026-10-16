#include <stdint.h>
uint64_t fold(uint64_t crc)
{
    uint64_t top = crc >> 32;
    return top ^ (crc << 8);
}
