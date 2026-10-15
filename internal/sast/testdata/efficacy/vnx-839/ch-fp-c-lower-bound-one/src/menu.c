#include <stdlib.h>

static const char *items[11];

const char *pick(const char *arg)
{
    int n = atoi(arg);
    if (n > 10 || n < 1)
        return NULL;
    return items[n];
}

const char *pick2(const char *arg)
{
    int k = atoi(arg);
    if (k <= 0) return NULL;
    if (k > 10) return NULL;
    return items[k];
}
