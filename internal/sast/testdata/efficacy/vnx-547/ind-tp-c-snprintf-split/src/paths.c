#include <stdio.h>

int build_path(const char *dir, const char *name)
{
    char path[512];

~>    snprintf(path, 512,
             "%s/%s.cache", dir, name);
    return open_cache(path);
}
