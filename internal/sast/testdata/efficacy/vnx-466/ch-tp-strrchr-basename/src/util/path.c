#include <string.h>

const char *path_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
~>    return slash + 1;
}
