#include <netdb.h>
#include <netinet/in.h>
#include <string.h>

unsigned short first_port(const char *host, const char *svc)
{
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, svc, NULL, &res) != 0)
        return 0;
~>    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    unsigned short port = ntohs(sin->sin_port);
    freeaddrinfo(res);
    return port;
}
