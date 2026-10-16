#include <stdlib.h>
#include <string.h>

#define SLOTS 64

struct slot { int used; char data[128]; };

struct slot *pool_create(const char *count_arg)
{
    int n = atoi(count_arg);
    struct slot *extra = calloc(n, sizeof(struct slot));
    free(extra);
    return malloc(SLOTS * sizeof(struct slot));
}

char *dup_name(const char *s)
{
    char *p = malloc(strlen(s) + 1);
    if (p)
        strcpy(p, s);
    return p;
}

long *alloc_longs(size_t n)
{
    return reallocarray(NULL, n, sizeof(long));
}
