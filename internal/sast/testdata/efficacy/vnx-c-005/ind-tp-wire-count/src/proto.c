#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct record { uint32_t id; uint32_t flags; char tag[24]; };

struct record *decode_records(const unsigned char *pkt, size_t pktlen)
{
    uint32_t count;
    memcpy(&count, pkt, sizeof(count));
    count = ntohl(count);
~>    struct record *recs = malloc(count * sizeof(struct record));
    if (recs == NULL)
        return NULL;
    memcpy(recs, pkt + 4, count * sizeof(struct record));
    return recs;
}

char *decode_name(const unsigned char *pkt)
{
    uint32_t len = ntohl(*(const uint32_t *)pkt);
~>    char *name = malloc(len + 1);
    if (name == NULL)
        return NULL;
    memcpy(name, pkt + 4, len);
    name[len] = '\0';
    return name;
}
