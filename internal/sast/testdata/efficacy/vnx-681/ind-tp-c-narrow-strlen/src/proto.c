#include <stdint.h>
#include <stdio.h>
#include <string.h>

size_t encode_name(uint8_t *out, const char *name)
{
~>    uint16_t name_len = strlen(name);
~>    out[2] = (uint8_t)strlen(name);
    memcpy(out + 3, name, name_len);
    return 3 + name_len;
}
