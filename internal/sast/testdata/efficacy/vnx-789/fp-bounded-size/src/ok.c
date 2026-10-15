#include <stdlib.h>
#define MAX_COUNT 4096

char *make(char **argv)
{
    int count = atoi(argv[1]);
    if (count <= 0 || count > MAX_COUNT)
        return NULL;
    return malloc(count);
}

char *make2(const char *s)
{
    size_t n = strtoul(s, NULL, 10);
    if (n >= 1024) return NULL;
    char *p = malloc(n);
    return p;
}

char *make3(const char *s)
{
    int n = atoi(s);
    n = MIN(n, MAX_COUNT);
    return malloc(n);
}
