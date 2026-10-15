#include <stdlib.h>

void grow(char **pp, size_t n)
{
    char *p = *pp;
    p = realloc(p, n);
    p[0] = 0;
    *pp = p;
}
