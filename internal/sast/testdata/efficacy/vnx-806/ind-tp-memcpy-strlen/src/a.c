#include <string.h>
void copy_name(const char *src)
{
    char dst[32];
~>    memcpy(dst, src, strlen(src));
    dst[0] = dst[0];
}
