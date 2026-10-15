#include <stdlib.h>
#include <string.h>

int copy_in(char **out, const char *src, size_t n)
{
    char *buf;
    if ((buf = malloc(n)) == NULL)
        return -1;
    memcpy(buf, src, n);
    *out = buf;
    return 0;
}
