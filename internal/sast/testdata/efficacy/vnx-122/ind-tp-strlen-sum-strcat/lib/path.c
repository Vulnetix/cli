#include <stdlib.h>
#include <string.h>

char *join_path(const char *dir, const char *base)
{
~>    char *full = malloc(strlen(dir) + strlen(base));
    if (!full)
        return NULL;
    strcpy(full, dir);
    strcat(full, base);
    return full;
}
