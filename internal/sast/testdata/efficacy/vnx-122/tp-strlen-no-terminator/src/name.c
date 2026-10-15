#include <stdlib.h>
#include <string.h>

char *copy_name(const char *name)
{
~>    char *out = malloc(strlen(name));
    if (out == NULL)
        return NULL;
    strcpy(out, name);
    return out;
}
