#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct record {
    uint32_t id;
    uint32_t flags;
};

struct record *read_records(const uint8_t *pkt, size_t *out)
{
    uint32_t count = ntohl(*(const uint32_t *)pkt);
~>    struct record *recs = malloc(count * sizeof(struct record));

    if (recs == NULL)
        return NULL;
    memcpy(recs, pkt + 4, count * sizeof(struct record));
    *out = count;
    return recs;
}

char *read_name(const uint8_t *pkt)
{
    uint32_t len = ntohl(*(const uint32_t *)pkt);
~>    char *name = malloc(len + 1);
    memcpy(name, pkt + 4, len);
    name[len] = '\0';
    return name;
}
