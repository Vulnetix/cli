#include <stdint.h>

uint32_t read_word(void *buf, size_t n)
{
~>    return *((uint32_t *)buf + n * sizeof(uint32_t));
}

void put_short(unsigned char *frame, size_t k, short v)
{
~>    short *dst = (short *) frame + k * sizeof(short);
    *dst = v;
}
