#include <stdlib.h>

int build(char **a, char **b)
{
    *a = malloc(16);
    if (*a == NULL)
        goto fail;
    *b = malloc(32);
    if (*b == NULL)
        goto fail_a;
    return 0;
fail_a:
    free(*a);
fail:
    return -1;
}

int build2(char **a)
{
    *a = malloc(8);
    if (*a == NULL)
        goto fail;
    return 0;
fail:
    return -1;
}
