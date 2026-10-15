#include <stdlib.h>

#define NAME_LEN 255

int canon(const char *arg, char **out)
{
    char real[NAME_LEN];
~>    char *r = realpath(arg, real);
    if (r == NULL)
        return -1;
    *out = strdup(real);
    return 0;
}
