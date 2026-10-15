#include <stdio.h>
#include <string.h>

void fill(struct ops *ops, char *buf, size_t n, const char *src)
{
    my_strlcpy(buf, src, n);
    ops->strlcpy(buf, src, n);
    snprintf(buf, n, "%s", src);
    strncpy(buf, src, n - 1);
    /* strlcpy(buf, src, n) is BSD only */
    // _stricmp(a, b)
    puts("call strcpy_s(dst, n, src) on Windows");
}
