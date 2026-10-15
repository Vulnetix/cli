#include <limits.h>
#include <stdlib.h>
#include <string.h>

int resolve_upload(const char *name, char *out, size_t outlen)
{
    char resolved[256];
~>    if (realpath(name, resolved) == NULL)
        return -1;
    strncpy(out, resolved, outlen - 1);
    out[outlen - 1] = '\0';
    return 0;
}

#define NAME_LEN 128

int canonical(const char *p)
{
    char buf[NAME_LEN];
~>    char *r = realpath( p,
                        buf );
    return r != NULL;
}
