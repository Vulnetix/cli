#include <limits.h>
#include <stdlib.h>
#include <string.h>

int resolve_config(const char *p, char *dst, size_t n)
{
    char out[PATH_MAX];
    if (realpath(p, out) == NULL)
        return -1;
    strncpy(dst, out, n);
    return 0;
}

int resolve_plugin(const char *name)
{
    char out[128];
~>    if (!realpath(name, out))
        return -1;
    return load_plugin(out);
}
