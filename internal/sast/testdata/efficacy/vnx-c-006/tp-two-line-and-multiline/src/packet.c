#include <alloca.h>
#include <arpa/inet.h>
#include <stdint.h>

void handle(const uint8_t *pkt)
{
    uint32_t len = ntohl(*(const uint32_t *)pkt);
~>    uint8_t *copy = alloca(len);
    copy_payload(copy, pkt + 4, len);
}

void handle_records(const uint8_t *pkt, size_t n)
{
~>    struct rec *recs = alloca(
        n * sizeof(struct rec));
    decode(recs, pkt, n);
}
