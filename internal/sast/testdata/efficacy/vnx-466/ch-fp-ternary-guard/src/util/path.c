#include <string.h>

const char *path_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

const char *ext_of(const char *name)
{
    const char *dot = strrchr(name, '.');
    if (dot == NULL)
        return "";
    return dot + 1;
}
