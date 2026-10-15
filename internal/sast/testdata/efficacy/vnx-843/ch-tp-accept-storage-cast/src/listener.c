#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

int accept_client(int lfd, char *out, size_t outlen)
{
    struct sockaddr_storage peer;
    socklen_t len = sizeof(peer);
    int cfd = accept(lfd, (struct sockaddr *)&peer, &len);
    if (cfd < 0)
        return -1;
~>    struct sockaddr_in6 *p6 = (struct sockaddr_in6 *)&peer;
    inet_ntop(AF_INET6, &p6->sin6_addr, out, outlen);
    return cfd;
}
