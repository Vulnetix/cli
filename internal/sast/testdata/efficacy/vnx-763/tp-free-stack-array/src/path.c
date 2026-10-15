#include <stdlib.h>
#include <string.h>

int build_path(const char *dir, const char *name)
{
    char path[4096];
    char *parts[8];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int rc = open_path(path);
~>    free(path);
~>    free(parts);
    return rc;
}
