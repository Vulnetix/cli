#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>

void log_peer(const struct sockaddr *sa)
{
    char buf[INET_ADDRSTRLEN];
~>    const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;

    inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
    printf("peer %s:%d\n", buf, ntohs(sin->sin_port));
}

int peer_port(int fd)
{
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    if (getpeername(fd, (struct sockaddr *)&ss, &len) < 0)
        return -1;
~>    return ntohs(((struct sockaddr_in6 *) &ss)->sin6_port);
}
