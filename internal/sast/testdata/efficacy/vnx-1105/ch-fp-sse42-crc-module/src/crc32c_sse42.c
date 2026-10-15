#include <stdint.h>
#include <stddef.h>

uint32_t crc32c_hw(uint32_t crc, const unsigned char *p, size_t n)
{
    while (n--) {
        __asm__ __volatile__("crc32b %1, %0" : "+r"(crc) : "rm"(*p++));
    }
    return crc;
}
