#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

struct record {
    uint32_t id;
    uint32_t flags;
    char name[32];
};

struct record *parse_records(const uint8_t *buf, size_t buflen, uint32_t *out_count)
{
    if (buflen < 4) {
        return NULL;
    }
    uint32_t count = ntohl(*(const uint32_t *)buf);
    const uint8_t *p = buf + 4;

~>    struct record *out = malloc(count * sizeof(struct record));
    if (out == NULL) {
        return NULL;
    }
    for (uint32_t i = 0; i < count; i++) {
        memcpy(&out[i], p, sizeof(struct record));
        p += sizeof(struct record);
    }
    *out_count = count;
    return out;
}
