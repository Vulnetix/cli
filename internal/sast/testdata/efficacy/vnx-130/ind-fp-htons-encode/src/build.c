#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

size_t build_frame(uint8_t *out, const uint8_t *data, uint16_t dlen)
{
    uint16_t wire = htons(dlen);
    memcpy(out, &wire, sizeof(wire));
    memcpy(out + 2, data, dlen);
    return 2 + (size_t)dlen;
}
