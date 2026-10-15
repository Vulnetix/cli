#include <stdlib.h>
#define MAX_ITEMS 256

int *make(void)
{
    int depth = atoi("12");
    int *p = malloc(MAX_ITEMS * sizeof(int));
    (void)depth;
    return p;
}
