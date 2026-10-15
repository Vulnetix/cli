#include <string.h>

void join(const char *a, const char *b)
{
    char dst[64];
    strcpy(dst, a);
~>    strncat(dst, b, sizeof(dst));
}
