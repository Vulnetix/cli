#include <stdlib.h>
#include <string.h>

char *strbuf_clone(const char *src, size_t len)
{
    char *copy = malloc(len + 1);
    if (copy == NULL)
        return NULL;
    memcpy(copy, src, len);
    copy[len] = '\0';
    return copy;
}
