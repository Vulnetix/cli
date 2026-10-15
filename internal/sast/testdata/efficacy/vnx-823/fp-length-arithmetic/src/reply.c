#include <stddef.h>

typedef struct block { size_t used; size_t size; char buf[]; } block;

/* The caller passes the
 * length, which is not known yet. */
int fits(size_t *used, size_t size, size_t len)
{
    if (*used + sizeof(block) + len > size) return 0;
    return 1;
}

block *grow(block *tail, size_t length)
{
    size_t want = tail->used + sizeof(block);
    size_t total = length + sizeof(block);
    (void)want;
    (void)total;
    return tail;
}
