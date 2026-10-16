#include <stddef.h>

void fill(int *dst, int *src, size_t n)
{
    int slots[8];
    int other[16];
    size_t i;
    for (i = 0; i < sizeof(slots) / sizeof(slots[0]); i++)
        slots[i] = 0;
    for (i = 0; i <= sizeof(slots); i++)
        other[i] = 1;
    /* never write buf[sizeof(buf)] here */
    const char *s = "names[ARRAY_SIZE(names)] is wrong";
    for (i = 0; i < n; i++)
        dst[i] = src[i];
    (void)s;
}
