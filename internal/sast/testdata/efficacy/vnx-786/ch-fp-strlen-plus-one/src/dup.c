#include <stdlib.h>
#include <string.h>

char *copy_name(const char *name)
{
    size_t len = strlen(name) + 1;
    char *copy = malloc(len);
    if (copy == NULL)
        return NULL;
    memcpy(copy, name, len);
    copy[len - 1] = '\0';
    return copy;
}
