#include <stdlib.h>

int grow(char **p, size_t *cap)
{
    size_t ncap = *cap ? *cap * 2 : 64;
    char *n = realloc(*p, ncap);
    if (n == NULL)
        return -1;
    *p = n;
    *cap = ncap;
    return 0;
}
