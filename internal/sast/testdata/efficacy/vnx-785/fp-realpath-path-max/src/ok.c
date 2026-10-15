#include <limits.h>
#include <stdlib.h>
#include <sys/param.h>

int a(const char *p)
{
    char resolved[PATH_MAX];
    return realpath(p, resolved) != NULL;
}

int b(const char *p)
{
    char resolved[PATH_MAX + 1];
    return realpath(p, resolved) != NULL;
}

int c(const char *p)
{
    char out[MAXPATHLEN];
    return realpath(p, out) != NULL;
}

int d(const char *p)
{
    char big[4096];
    return realpath(p, big) != NULL;
}
