#include <stdint.h>

uint8_t low_byte(uint32_t v)
{
    uint32_t value = v;
    uint8_t *b = (uint8_t *)&value;
    long n = 0;
    char *c = (char *)&n;
    return b[0] + c[0];
}
