#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct rec { uint32_t id; uint32_t len; };

struct rec *grow(struct rec *recs, const uint32_t *wire)
{
    uint32_t n = ntohl(wire[0]);
~>    recs = realloc(recs, n * sizeof(struct rec));
    return recs;
}

char *decode(const char *field)
{
    unsigned long width = strtoul(field, NULL, 10);
    unsigned long height = strtoul(field + 8, NULL, 10);
~>    char *pixels = malloc(width * height * 4);
    return pixels;
}
