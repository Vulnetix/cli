#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>

int peer_port(const struct sockaddr *sa)
{
    switch (sa->sa_family) {
    case AF_INET:
        return ntohs(((const struct sockaddr_in *)sa)->sin_port);
    case AF_INET6:
        return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    default:
        return -1;
    }
}

int bind_any(int fd, unsigned short port)
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    return bind(fd, (struct sockaddr *)&sin, sizeof(sin));
}

void fill(struct sockaddr_storage *ss)
{
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;
    in6->sin6_family = AF_INET6;
    in6->sin6_addr = in6addr_any;
}

int first_v4(struct addrinfo *res)
{
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        if (p->ai_family != AF_INET)
            continue;
        return ntohs(((struct sockaddr_in *)p->ai_addr)->sin_port);
    }
    return -1;
}
