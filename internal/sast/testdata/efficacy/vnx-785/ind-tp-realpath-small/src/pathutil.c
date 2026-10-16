#include <limits.h>
#include <stdlib.h>
#include <string.h>

int canonical_dir(const char *name, char *out, size_t outlen)
{
    char resolved[256];
~>    if (realpath(name, resolved) == NULL)
        return -1;
    strncpy(out, resolved, outlen);
    return 0;
}
