#include <string.h>
#include <stdio.h>

void build(char *dst, size_t n, const char *src)
{
    strncpy(dst, src, n - 1);
    my_strlcpy(dst, src, n);
    snprintf(dst, n, "%s", src);
    const char *msg = "use strlcpy( here";
    /* strlcpy(dst, src, n); */
    obj.strlcpy(dst);
}
