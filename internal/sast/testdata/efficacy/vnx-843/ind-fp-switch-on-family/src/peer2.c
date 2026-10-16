#include <sys/socket.h>
#include <netinet/in.h>

int peer_port(const struct sockaddr *sa)
{
    switch (sa->sa_family) {
    case AF_INET: {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        return ntohs(sin->sin_port);
    }
    case AF_INET6: {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
        return ntohs(s6->sin6_port);
    }
    default:
        return -1;
    }
}
