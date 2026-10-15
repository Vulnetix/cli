#include <cstdint>
#include <arpa/inet.h>
#include <sys/socket.h>

uint8_t *readPacket(int fd)
{
    uint32_t wire = 0;
    ::recv(fd, &wire, sizeof(wire), 0);
    size_t n = ntohl(wire);
~>    auto *data = new uint8_t[n];
    ::recv(fd, data, n, 0);
    return data;
}
