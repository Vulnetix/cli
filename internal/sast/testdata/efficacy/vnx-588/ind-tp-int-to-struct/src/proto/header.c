#include <stdint.h>
#include <string.h>

struct header {
    uint16_t type;
    uint16_t len;
    uint32_t seq;
};

void stamp(uint32_t seq)
{
    int flags = 0;
~>    struct header *h = (struct header *)&flags;
    h->seq = seq;
}
