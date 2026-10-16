#include <string.h>

void copy_label(char *dst, const char *src)
{
    strncpy(dst, src, 64);
    dst[63] = '\0';
}
