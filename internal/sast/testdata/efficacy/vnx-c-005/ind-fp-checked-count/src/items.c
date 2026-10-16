#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_ITEMS 4096

struct item { uint64_t key; uint64_t val; };

struct item *alloc_items(const unsigned char *pkt)
{
    uint32_t count = ntohl(*(const uint32_t *)pkt);
    if (count > SIZE_MAX / sizeof(struct item))
        return NULL;
    return malloc(count * sizeof(struct item));
}

char *alloc_label(const char *arg)
{
    long n = strtol(arg, NULL, 10);
    if (n < 0 || n > MAX_ITEMS)
        return NULL;
    return malloc(n + 1);
}
