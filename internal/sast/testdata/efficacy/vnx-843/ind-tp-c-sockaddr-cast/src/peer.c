#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void log_peer(const struct sockaddr *sa)
{
    char buf[64];
~>    const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
    inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf);
    printf("peer %s:%d\n", buf, ntohs(sin->sin_port));
}
