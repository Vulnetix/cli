#include <stdint.h>
#include <string.h>

int tlv_value(const uint8_t *buf, size_t len, uint8_t *out)
{
~>    memcpy(out, buf + 4, len - 4);
    return 0;
}
