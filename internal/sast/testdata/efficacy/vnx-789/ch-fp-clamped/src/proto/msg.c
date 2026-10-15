#include <arpa/inet.h>
#include <stdlib.h>

#define MAX_BODY (1u << 20)

int read_msg(const unsigned char *wire, unsigned char **out)
{
    uint32_t len = ntohl(*(const uint32_t *)wire);
    if (len == 0 || len > MAX_BODY)
        return -1;
    *out = malloc(len);

    int n = atoi(getenv("WORKERS"));
    n = n > 64 ? 64 : n;
    int *ids = calloc(n, sizeof *ids);

    long want = strtol(getenv("CACHE_KB"), NULL, 10);
    size_t sz = MIN(want, 4096) * 1024;
    char *cache = malloc(sz);
    (void)cache;
    (void)ids;
    return 0;
}
