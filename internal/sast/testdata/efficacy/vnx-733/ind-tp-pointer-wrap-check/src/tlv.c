#include <stddef.h>
#include <stdint.h>

int tlv_next(const uint8_t *buf, const uint8_t *end, size_t len, const uint8_t **out)
{
    const uint8_t *cursor = buf;
~>    if (cursor + len < cursor)
        return -1;
    if (cursor + len > end)
        return -1;
    *out = cursor + len;
    return 0;
}
