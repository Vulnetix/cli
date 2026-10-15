#include <stdlib.h>
#include <string.h>

char *dup_name(const char *name)
{
    char *copy = malloc(strlen(name) + 1);
    strcpy(copy, name);
    return copy;
}
