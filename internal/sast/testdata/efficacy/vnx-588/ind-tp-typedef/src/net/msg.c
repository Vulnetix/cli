#include <stdint.h>

typedef struct {
    uint8_t version;
    uint8_t flags;
    uint16_t length;
} msg_hdr_t;

uint16_t peek_length(void)
{
    uint32_t word = 0;
    read_word(&word);
~>    msg_hdr_t *h = (msg_hdr_t *)&word;
    return h->length;
}
