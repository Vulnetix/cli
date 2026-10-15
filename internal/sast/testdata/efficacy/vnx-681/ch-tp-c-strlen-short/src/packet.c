#include <string.h>
#include <stdint.h>

void put_name(uint8_t *out, const char *name)
{
~>    unsigned short len = strlen(name);
    out[0] = len >> 8;
}
