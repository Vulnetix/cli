#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

struct hdr { uint16_t type; uint16_t len; };

void parse(const unsigned char *pkt)
{
    char payload[512];
    const struct hdr *h = (const struct hdr *)pkt;
    uint16_t len = ntohs(h->len);
~>    memcpy(payload, pkt + sizeof(*h), len);
    handle(payload, len);
}
