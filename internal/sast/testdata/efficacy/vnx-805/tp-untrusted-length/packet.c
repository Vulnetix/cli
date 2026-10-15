#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

struct hdr { uint16_t length; uint16_t type; };

void handle(const unsigned char *pkt, char **argv) {
    char payload[512];
    char buf[128];
    const struct hdr *h = (const struct hdr *)pkt;
    uint16_t len = ntohs(h->length);
    log_type(h->type);
~>    memcpy(payload, pkt + sizeof(*h), len);
    int n = atoi(argv[2]);
~>    memset(buf, 'A', n);
}
