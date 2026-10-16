#include <limits.h>
#include <stdlib.h>

char *resolve(const char *name)
{
    char *p = realpath(name, NULL);
    return p;
}

int resolve_big(const char *name)
{
    char buf[PATH_MAX];
    if (realpath(name, buf) == NULL)
        return -1;
    return 0;
}
