#include <stdlib.h>
#include <string.h>

char *dup_header(const char *value)
{
    size_t len = strlen(value);
~>    char *copy = xmalloc(len);
    strcpy(copy, value);
    return copy;
}
