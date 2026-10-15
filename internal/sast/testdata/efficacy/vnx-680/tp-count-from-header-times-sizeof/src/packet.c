#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

struct record { uint32_t id; char name[32]; };

struct record *parse_records(const uint8_t *buf, size_t len) {
    uint32_t count = ntohl(*(const uint32_t *)buf);
    struct record *out;
~>    out = malloc(count * sizeof(struct record));
    if (out == NULL) {
        return NULL;
    }
    return out;
}
