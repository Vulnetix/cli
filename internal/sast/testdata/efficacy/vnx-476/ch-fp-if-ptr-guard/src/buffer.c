#include <stdlib.h>
#include <string.h>

char *copy_buffer(const char *src, size_t n)
{
    char *dst = malloc(n + 1);
    if (dst) {
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return dst;
}

char *dup_name(const char *name)
{
    char *copy;
    copy = strdup(name);
    if (unlikely(copy == NULL))
        return NULL;
    copy[0] = 'X';
    return copy;
}
