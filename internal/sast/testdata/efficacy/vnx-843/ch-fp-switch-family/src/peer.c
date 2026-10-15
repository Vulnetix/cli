#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

const char *peer_str(const struct sockaddr_storage *ss, char *buf, socklen_t n)
{
    switch (ss->ss_family) {
    case AF_INET: {
        const struct sockaddr_in *a = (const struct sockaddr_in *)ss;
        return inet_ntop(AF_INET, &a->sin_addr, buf, n);
    }
    case AF_INET6: {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)ss;
        return inet_ntop(AF_INET6, &a6->sin6_addr, buf, n);
    }
    default:
        return NULL;
    }
}
