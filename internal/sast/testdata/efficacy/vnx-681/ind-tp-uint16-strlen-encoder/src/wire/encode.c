#include <stdint.h>
#include <string.h>

size_t encode_name(uint8_t *out, const char *name, const char *tag)
{
~>    uint16_t name_len = strlen(name);
    out[0] = (uint8_t)(name_len >> 8);
    out[1] = (uint8_t)(name_len & 0xff);
~>    out[2] = (uint8_t)strlen(tag);
    memcpy(out + 3, name, name_len);
    return 3 + name_len;
}
