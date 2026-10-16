#include <stdlib.h>
#include <string.h>

char *copy_name(const char *name, size_t n)
{
    char *buf = malloc(n + 1);
~>    strcpy(buf, name);
    return buf;
}
