#include <stdlib.h>

#define RESOLVED_LEN 4096

int canon(const char *arg, char **out)
{
    char real[RESOLVED_LEN];
    char *r = realpath(arg, real);
    if (r == NULL)
        return -1;
    *out = strdup(real);
    return 0;
}
