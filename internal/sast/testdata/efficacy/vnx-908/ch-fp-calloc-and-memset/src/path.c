#include <stdlib.h>
#include <string.h>

char *join_path(const char *dir, const char *name)
{
    char *out = calloc(1, strlen(dir) + strlen(name) + 2);
    char tmp[32];
    if (out == NULL)
        return NULL;
    memset(tmp, 0, sizeof(tmp));
    strcat(out, dir);
    strcat(out, "/");
    strcat(out, name);
    strcat(tmp, "x");
    return out;
}
