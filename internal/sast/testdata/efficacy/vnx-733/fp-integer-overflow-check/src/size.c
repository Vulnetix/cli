#include <stddef.h>

int alloc_total(size_t a, size_t b, unsigned char *p, unsigned char *end, size_t n) {
    if (a + b < a)
        return -1;
    if (n > (size_t)(end - p))
        return -1;
    int count = 0;
    if (count + 1 < count)
        return -1;
    return 0;
}
