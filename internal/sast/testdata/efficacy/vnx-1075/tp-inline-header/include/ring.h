#ifndef RING_H
#define RING_H

static inline int ring_pop(struct ring *r, int *out) {
    unsigned head;
reload:
    head = r->head;
    if (head == r->tail)
        return -1;
    if (!__sync_bool_compare_and_swap(&r->head, head, head + 1))
~>        goto reload;
    *out = r->slots[head % r->size];
    return 0;
}

#endif
