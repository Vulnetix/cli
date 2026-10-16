#include <string.h>

void queue_pop(char *buf, size_t n)
{
    memmove(buf, buf + 1, n - 1);
}

void copy(char *dst, const char *src, size_t n)
{
    memcpy(dst, src, n);
}
