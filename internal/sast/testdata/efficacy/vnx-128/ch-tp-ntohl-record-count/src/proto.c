#include <stdlib.h>
#include <arpa/inet.h>

struct rec { int a, b; };

struct rec *parse(const struct hdr *h)
{
    uint32_t count = ntohl(h->count);
~>    struct rec *r = malloc(count * sizeof(struct rec));
    return r;
}
