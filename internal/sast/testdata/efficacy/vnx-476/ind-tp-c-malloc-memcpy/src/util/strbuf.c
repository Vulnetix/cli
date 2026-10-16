#include <stdlib.h>
#include <string.h>

char *strbuf_clone(const char *src, size_t len)
{
    char *copy = (char *) malloc(len + 1);
~>    memcpy(copy, src, len + 1);
    return copy;
}
