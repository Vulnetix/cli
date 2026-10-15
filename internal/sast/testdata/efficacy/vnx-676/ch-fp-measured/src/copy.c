#include <string.h>

int copy(char dst[64], const char *src)
{
    if (strlen(src) >= 64)
        return -1;
    strcpy(dst, src);
    return 0;
}
