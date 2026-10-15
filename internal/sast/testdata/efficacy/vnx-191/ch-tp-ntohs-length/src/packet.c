#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

struct hdr { uint16_t type; uint16_t len; };

void handle(const uint8_t *pkt, uint8_t *payload)
{
    const struct hdr *h = (const struct hdr *)pkt;
    uint16_t plen = ntohs(h->len);
~>    memcpy(payload, pkt + sizeof(*h), plen - sizeof(*h));
}
