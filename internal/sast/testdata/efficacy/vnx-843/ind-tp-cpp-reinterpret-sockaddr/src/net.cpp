#include <sys/socket.h>
#include <netinet/in.h>

uint16_t port_of(const sockaddr_storage &addr)
{
~>    auto *in6 = reinterpret_cast<const sockaddr_in6 *>(&addr);
    return ntohs(in6->sin6_port);
}
