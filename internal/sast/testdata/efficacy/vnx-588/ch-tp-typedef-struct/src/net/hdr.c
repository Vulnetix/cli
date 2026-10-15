#include <stdint.h>

typedef struct {
    uint16_t len;
    uint16_t kind;
} msg_hdr_t;

uint16_t peek(void)
{
    uint32_t word = 0;
~>    msg_hdr_t *h = (msg_hdr_t *)&word;
    return h->kind;
}
