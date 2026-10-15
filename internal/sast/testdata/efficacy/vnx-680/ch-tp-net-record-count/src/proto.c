#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

struct rec { uint32_t id; char name[64]; };

struct rec *read_records(const uint8_t *pkt)
{
    uint32_t n = ntohl(*(const uint32_t *)pkt);
~>    struct rec *r = malloc(n * sizeof(struct rec));
    return r;
}
