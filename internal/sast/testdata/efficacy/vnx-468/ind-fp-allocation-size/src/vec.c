#include <stdlib.h>
#include <string.h>

int *make_ints(size_t n)
{
    int *v = malloc(n * sizeof(int));
    if (v == NULL)
        return NULL;
    memset(v, 0, n * sizeof(int));
    return v;
}
