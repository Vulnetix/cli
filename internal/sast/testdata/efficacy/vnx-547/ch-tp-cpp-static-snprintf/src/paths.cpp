#include <cstdio>

const char *join_path(const char *dir, const char *name)
{
    static char path[4096];
~>    std::snprintf(path, 4096,
                  "%s/%s", dir, name);
    return path;
}
