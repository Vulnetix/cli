#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

struct hdr { uint16_t type; uint16_t len; };

int handle_packet(const unsigned char *pkt, size_t pktlen)
{
    const struct hdr *h = (const struct hdr *)pkt;
    unsigned char payload[512];
    uint16_t len = ntohs(h->len);
    if (len > sizeof(payload) || len > pktlen - sizeof(*h))
        return -1;
    memcpy(payload, pkt + sizeof(*h), len);
    return dispatch(payload, len);
}
