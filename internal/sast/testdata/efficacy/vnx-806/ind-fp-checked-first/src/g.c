#include <string.h>
int set(const char *src)
{
    char dst[32];
    if (strlen(src) >= sizeof(dst))
        return -1;
    memcpy(dst, src, strlen(src) + 1);
    return 0;
}
