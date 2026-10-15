#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

#define MAX_ITEMS 4096

void *read_items(const uint8_t *pkt)
{
    uint32_t n = ntohl(*(const uint32_t *)pkt);
    if (n == 0 || n > MAX_ITEMS)
        return NULL;
    return malloc(n * sizeof(uint64_t));
}
