#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct entry { uint64_t key; uint64_t val; };

struct entry *read_entries(const uint8_t *buf)
{
    uint32_t count = ntohl(*(const uint32_t *)buf);
    if (count > SIZE_MAX / sizeof(struct entry))
        return NULL;
    struct entry *a = malloc(count * sizeof(struct entry));
    struct entry *b = calloc(count, sizeof(struct entry));
    struct entry *c = reallocarray(NULL, count, sizeof(struct entry));
    free(b);
    free(c);
    return a;
}
