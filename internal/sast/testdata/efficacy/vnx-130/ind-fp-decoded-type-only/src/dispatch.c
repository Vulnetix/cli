#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

int route(const uint8_t *msg, uint8_t *hdr_copy)
{
    uint16_t kind = ntohs(*(const uint16_t *)msg);
    memcpy(hdr_copy, msg, 4);
    switch (kind) {
    case 1: return handle_ping(msg);
    case 2: return handle_data(msg);
    default: return -1;
    }
}
