#include <stdlib.h>

int test_grow(void)
{
    char *p = malloc(16);
    p = realloc(p, 0);
    if (p != NULL)
        return 1;
    return 0;
}
