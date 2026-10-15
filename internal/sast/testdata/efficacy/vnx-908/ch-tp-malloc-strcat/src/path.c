#include <stdlib.h>
#include <string.h>

char *join_path(const char *dir, const char *name)
{
    char *out = malloc(strlen(dir) + strlen(name) + 2);
    if (out == NULL)
        return NULL;
~>    strcat(out, dir);
    strcat(out, "/");
    strcat(out, name);
    return out;
}
