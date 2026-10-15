#include <stdio.h>
#include <stdlib.h>

char *join_path(const char *dir, const char *file)
{
    char *out = malloc(64);
    if (!out)
        return NULL;
~>    sprintf(out,
            "%s/%s", dir, file);
    return out;
}
