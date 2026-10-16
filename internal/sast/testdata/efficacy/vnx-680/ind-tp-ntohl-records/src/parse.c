#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

struct record { uint32_t id; uint32_t flags; char tag[16]; };

struct record *parse_records(const uint8_t *buf, size_t len, uint32_t *n_out)
{
    uint32_t count;
    if (len < 4)
        return NULL;
    memcpy(&count, buf, sizeof count);
    count = ntohl(count);
    struct record *out;
~>    out = malloc(count * sizeof(struct record));
    if (out == NULL)
        return NULL;
    *n_out = count;
    return out;
}
