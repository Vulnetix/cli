static inline int ring_push(struct ring *r, int v)
{
restart:
    if (ring_full(r)) {
        ring_wait(r);
~>        goto restart;
    }
    r->buf[r->head++] = v;
    if (r->head == r->cap) {
        r->head = 0;
~>        goto restart;
    }
    return 0;
}
