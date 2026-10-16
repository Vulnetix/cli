#include <stdlib.h>

int run(size_t n)
{
~>    char *p = malloc(n);
    if (!p) return -1;
    p[0] = 0;
    p = malloc(n * 2);
    if (!p) return -1;
    free(p);
    return 0;
}
