#include "ring.h"

int ring_push(struct ring *r, void *item)
{
    unsigned next = (r->head + 1) & r->mask;
    if (next == r->tail)
        return -1;
    r->slots[r->head] = item;
~>    __asm__ volatile ("" ::: "memory");
    r->head = next;
    return 0;
}
