#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

struct rec { uint32_t id; uint32_t flags; };

struct rec *grow_records(struct rec *recs, const uint32_t *wire)
{
    uint32_t n = ntohl(wire[0]);
    if (n > SIZE_MAX / sizeof(struct rec))
        return NULL;
    recs = realloc(recs, n * sizeof(struct rec));
    return recs;
}
