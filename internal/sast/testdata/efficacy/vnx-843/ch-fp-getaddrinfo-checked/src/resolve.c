#include <netdb.h>
#include <netinet/in.h>

unsigned short first_v4_port(const char *host, const char *svc)
{
    struct addrinfo *res = NULL, *ai;
    unsigned short port = 0;
    if (getaddrinfo(host, svc, NULL, &res) != 0)
        return 0;
    for (ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET)
            continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
        port = ntohs(sin->sin_port);
        break;
    }
    freeaddrinfo(res);
    return port;
}
