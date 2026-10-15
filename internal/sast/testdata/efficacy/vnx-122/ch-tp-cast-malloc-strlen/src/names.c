#include <stdlib.h>
#include <string.h>

char *dup_name(const char *name)
{
    char *copy;
~>    copy = (char *)malloc(strlen(name));
    if (copy == NULL)
        return NULL;
    strcpy(copy, name);
    return copy;
}
