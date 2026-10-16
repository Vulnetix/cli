#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#define MIN(a,b) ((a)<(b)?(a):(b))
struct hdr { uint16_t length; uint8_t body[]; };
int parse(const struct hdr *h)
{
    uint8_t payload[64];
    size_t n = MIN(ntohs(h->length), sizeof(payload));
    memcpy(payload, h->body, n);
    uint16_t len = ntohs(h->length);
    if (len > sizeof(payload))
        return -1;
    memcpy(payload, h->body, len);
    return 0;
}
