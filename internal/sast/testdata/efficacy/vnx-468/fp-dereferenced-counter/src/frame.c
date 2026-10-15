#include <stddef.h>

struct frame_header { unsigned int len; };

/* *used is the counter's value, not pointer arithmetic on used. */
int frame_fits(size_t *used, size_t size, size_t len)
{
    if (*used + sizeof(struct frame_header) + len > size) return 0;
    *used += sizeof(struct frame_header);
    return 1;
}
