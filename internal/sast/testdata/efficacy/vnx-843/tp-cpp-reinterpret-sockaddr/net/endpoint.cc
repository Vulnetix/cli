#include <netinet/in.h>
#include <sys/socket.h>
#include <cstdint>

uint16_t endpoint_port(const sockaddr *addr)
{
~>    auto *in = reinterpret_cast<const sockaddr_in *>(addr);
    return ntohs(in->sin_port);
}
