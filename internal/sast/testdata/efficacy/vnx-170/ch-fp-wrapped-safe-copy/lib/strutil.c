#include <string.h>

/* "strncpy(dst, src, n)" is the call this wrapper replaces. */
static const char *usage = "strncpy(dst, src, sizeof(dst)) is unsafe";

void copy_field(char *dst, size_t size, const char *src)
{
    size_t len = strlen(src);
    if (len >= size)
        len = size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}
