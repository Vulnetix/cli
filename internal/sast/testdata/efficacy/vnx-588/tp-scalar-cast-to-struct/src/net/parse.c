#include <stdint.h>

struct header {
    uint16_t len;
    uint16_t type;
};

void handle(void)
{
    int flags = 0;
~>    struct header *h = (struct header *)&flags;
    h->len = 4;
}

void count_nodes(void)
{
    unsigned long count;
~>    ((struct node *) &count)->next = 0;
}
