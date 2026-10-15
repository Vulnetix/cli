#include <string.h>
#include <stdint.h>

static int checksum(const uint8_t *data, size_t n)
{
    uint8_t tmp[8];
    int sum = 0;
    memcpy(tmp, data, sizeof(tmp));
    for (size_t i = 0; i < sizeof(tmp) && i < n; i++)
        sum += tmp[i];
    return sum;
}

void encode_block(uint8_t *tmp, const uint8_t *src)
{
    /* the caller passes a 64-byte block */
    memcpy(tmp, src, 32);
}
