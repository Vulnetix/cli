#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

struct hdr { uint16_t type; uint16_t len; };

void handle_packet(const unsigned char *pkt)
{
    const struct hdr *h = (const struct hdr *)pkt;
    unsigned char payload[512];
    uint16_t len = ntohs(h->len);
~>    memcpy(payload, pkt + sizeof(*h), len);
    dispatch(payload, len);
}
