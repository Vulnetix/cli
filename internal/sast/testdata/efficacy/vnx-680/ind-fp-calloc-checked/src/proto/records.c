#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct record {
    uint32_t id;
    char name[32];
};

struct record *parse_records(const uint8_t *buf)
{
    uint32_t count = ntohl(*(const uint32_t *)buf);
    struct record *out = calloc(count, sizeof(struct record));
    return out;
}

struct record *grow_records(struct record *old, const char *arg)
{
    size_t n = strtoul(arg, NULL, 10);
    return reallocarray(old, n, sizeof(struct record));
}
