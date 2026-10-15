#include <stdint.h>

struct header { uint32_t len; };

const uint8_t *payload(const struct header *hdr)
{
    return (const uint8_t *)hdr + sizeof(struct header);
}

const char *body(const struct header *h)
{
    const char *p = (const char *) h + sizeof(*h);
    return p;
}

const struct header *next_header(const struct header *h)
{
    return h + 1;
}
