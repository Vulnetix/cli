#include <arpa/inet.h>
#include <cstring>
#include <cstdint>

struct FrameHeader { uint16_t kind; uint16_t length; };

void copy_body(const uint8_t *frame, uint8_t *body)
{
    const FrameHeader *fh = reinterpret_cast<const FrameHeader *>(frame);
~>    std::memcpy(body, frame + 4, ntohs(fh->length));
}
