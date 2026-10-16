#include <stddef.h>
#include <stdint.h>
#include <string.h>

int parse_frame(const uint8_t *buf, size_t len, uint8_t *out, size_t out_len)
{
    size_t payload = len - 6;

~>    if (payload < 0) {
        return -1;
    }
    if (payload > out_len) {
        return -2;
    }
    memcpy(out, buf + 6, payload);
    return (int)payload;
}
