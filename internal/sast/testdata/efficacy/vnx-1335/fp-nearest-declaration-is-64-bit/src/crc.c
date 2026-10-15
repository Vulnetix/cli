#include <stdint.h>

uint16_t crc16(const uint8_t *p, uint16_t crc, int n)
{
    while (n--) crc = (crc << 8) ^ p[n];
    return crc;
}

uint64_t crc64(const uint64_t table[8][256], uint64_t crc, int n)
{
    while (n--) {
        crc = table[4][(crc >> 32) & 0xff] ^
              table[7][crc >> 56];
    }
    return crc;
}
