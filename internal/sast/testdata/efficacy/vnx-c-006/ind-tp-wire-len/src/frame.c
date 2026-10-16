#include <alloca.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

int handle_frame(const unsigned char *pkt, size_t pktlen)
{
    uint32_t len = ntohl(*(const uint32_t *)pkt);
~>    uint8_t *copy = alloca(len);
    memcpy(copy, pkt + 4, len);
    return process_payload(copy, len);
}

void scratch_records(size_t nrec)
{
~>    struct rec { int a, b; } *tmp = __builtin_alloca(nrec * sizeof(*tmp));
    tmp[0].a = 0;
}
