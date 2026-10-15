#include <cstring>
#include <cstdint>
#include <arpa/inet.h>
#include <sys/socket.h>

void Conn::onFrame(const uint8_t *frame, const FrameHeader *fh)
{
    char body[256];
~>    std::memcpy(body, frame + 4, ntohs(fh->length));
}

void Conn::readBody(int sock, const FrameHeader *fh)
{
    char body[1024];
    uint32_t want = ntohl(fh->size);
~>    recv(sock, body, want, MSG_WAITALL);
}
