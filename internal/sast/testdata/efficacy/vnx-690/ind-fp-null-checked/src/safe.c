#include <stdlib.h>
#include <string.h>

char *dup_checked(const char *name, size_t n)
{
    char *buf = malloc(n + 1);
    if (buf == NULL)
        return NULL;
    strcpy(buf, name);
    return buf;
}
