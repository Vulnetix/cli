#include <stddef.h>
#include <string.h>

void put_u32(unsigned char *out, size_t idx, unsigned v)
{
    memcpy(out + idx * sizeof(unsigned), &v, sizeof v);
}

void put_i(char buf[], size_t idx, int v)
{
    memcpy(&buf[idx * sizeof(int)], &v, sizeof v);
}
