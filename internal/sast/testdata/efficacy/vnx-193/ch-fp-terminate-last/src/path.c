#include <limits.h>
#include <string.h>

void build(const char *dir)
{
    char path[PATH_MAX];
    strncpy(path, dir, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';
}
