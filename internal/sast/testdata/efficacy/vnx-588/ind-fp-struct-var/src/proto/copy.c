#include <string.h>
#include <stdint.h>

struct header {
    uint16_t type;
    uint16_t len;
};

struct header_v2 {
    uint16_t type;
    uint16_t len;
    uint32_t extra;
};

uint16_t header_type(const uint32_t *raw)
{
    struct header_v2 full;
    memcpy(&full, raw, sizeof(full));
    struct header *h = (struct header *)&full;
    uint32_t word = *raw;
    struct header copy;
    memcpy(&copy, &word, sizeof(copy));
    /* struct header *bad = (struct header *)&word; */
    return h->type + copy.type;
}
