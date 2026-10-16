#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>

struct hdr { uint16_t length; uint8_t body[]; };

int parse(const struct hdr *h)
{
    uint8_t payload[128];
    uint16_t len = ntohs(h->length);
~>    memcpy(payload, h->body, len);
    return payload[0];
}
