#include <stdlib.h>

static char table[256][16];

char *lookup(const char *s)
{
    int idx = atoi(s);
    if (idx < 0 || idx > 255)
        return NULL;
    char *p = (char *)&table[idx];
    return p;
}

int *alloc_ints(const char *s)
{
    long n = strtol(s, NULL, 10);
    int *arr = (int *)malloc((size_t)n * sizeof(int));
    long *tmp = (long *)calloc(n, sizeof(long));
    free(tmp);
    return arr;
}
