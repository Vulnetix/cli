#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

void parse(const unsigned char *pkt, size_t pkt_len)
{
    char payload[512];
    uint16_t len = ntohs(((const uint16_t *)pkt)[1]);
    if (len > sizeof(payload) || len + 4 > pkt_len)
        return;
    memcpy(payload, pkt + 4, len);
}

int process_heartbeat(SSL *s, unsigned char *p)
{
    unsigned int payload;
    n2s(p, payload);
    if (1 + 2 + payload + 16 > s->s3->rrec.length)
        return 0;
    memcpy(bp, p, payload);
    return 0;
}
