#include <stdint.h>
#include <stdlib.h>

void *alloc_two(size_t a, size_t b)
{
    size_t total = a + b;
    if (a + b < a)
        return NULL;
    uint32_t hdr = (uint32_t)a;
    if (hdr + 16u < hdr)
        return NULL;
    return malloc(total);
}
