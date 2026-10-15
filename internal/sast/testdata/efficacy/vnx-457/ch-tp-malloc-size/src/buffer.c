#include <stdlib.h>
#include <string.h>

char *dup_header(const char *src)
{
    size_t len;
~>    char *out = malloc(len + 1);
    if (out == NULL)
        return NULL;
    memcpy(out, src, strlen(src) + 1);
    return out;
}
