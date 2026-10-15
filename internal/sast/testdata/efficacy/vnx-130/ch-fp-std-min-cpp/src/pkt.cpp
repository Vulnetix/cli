#include <algorithm>
#include <cstring>
#include <arpa/inet.h>

void Packet::copyPayload(const unsigned char *p)
{
    uint16_t len = ntohs(*reinterpret_cast<const uint16_t *>(p));
    std::memcpy(payload_, p + 2, std::min<size_t>(len, sizeof(payload_)));
}
