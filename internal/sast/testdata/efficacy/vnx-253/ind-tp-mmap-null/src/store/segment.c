#include <sys/mman.h>
#include <stddef.h>
#include "segment.h"

void *segment_map(int fd, size_t len)
{
    void *base = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
~>    if (base == NULL)
        return NULL;
    return base;
}

int segment_map_ro(struct segment *seg)
{
    seg->addr = mmap(NULL, seg->len, PROT_READ, MAP_PRIVATE, seg->fd, 0);
~>    if (!seg->addr)
        return -1;
    return 0;
}
