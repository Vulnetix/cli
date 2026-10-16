#include <endian.h>
#include <stdint.h>
#include <string.h>

void tlv_value(const uint8_t *tlv, uint8_t *dst)
{
    uint32_t vlen;
    memcpy(&vlen, tlv + 4, sizeof(vlen));
    vlen = be32toh(vlen);
~>    memmove(dst,
            tlv + 8,
            vlen);
}
