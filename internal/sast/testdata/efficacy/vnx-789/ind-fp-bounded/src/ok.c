#include <stdlib.h>
#define MAX_COUNT 4096

void *alloc_checked(char **argv)
{
    int count = atoi(argv[1]);
    if (count <= 0 || count > MAX_COUNT)
        return NULL;
    return malloc(count);
}

void *alloc_clamped(const char *s)
{
    long n = strtol(s, NULL, 10);
    n = MIN(n, 1024);
    return malloc(n);
}
