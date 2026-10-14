#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

struct item { int v; };

struct item *alloc_items(const uint8_t *pkt)
{
    uint32_t count = ntohl(*(const uint32_t *)pkt);

    if (count > SIZE_MAX / sizeof(struct item))
        return NULL;
    return malloc(count * sizeof(struct item));
}

int *alloc_bounded(const char *arg)
{
    int n = atoi(arg);

    if (n <= 0 || n > 4096)
        return NULL;
    return malloc(n * sizeof(int));
}

void *alloc_builtin(const char *arg)
{
    size_t n = strtoul(arg, NULL, 10);
    size_t bytes;

    if (__builtin_mul_overflow(n, sizeof(long), &bytes))
        return NULL;
    return malloc(bytes);
}

void *alloc_calloc(const char *arg)
{
    size_t n = strtoul(arg, NULL, 10);
    return calloc(n, sizeof(long));
}
