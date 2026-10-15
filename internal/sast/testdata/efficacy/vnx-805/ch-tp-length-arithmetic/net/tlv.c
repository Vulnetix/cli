#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>

struct tlv { uint16_t type; uint16_t len; uint8_t data[]; };

int parse_tlv(const struct tlv *t, uint8_t *value)
{
    uint16_t vlen;

    vlen = ntohs(t->len);
~>    memcpy(value, t->data, vlen - 4);
    return vlen;
}
