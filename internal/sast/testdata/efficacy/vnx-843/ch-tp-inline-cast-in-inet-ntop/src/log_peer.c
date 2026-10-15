#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void log_peer(int fd)
{
    struct sockaddr_storage ss;
    socklen_t len = sizeof ss;
    char host[INET6_ADDRSTRLEN];

    if (getpeername(fd, (struct sockaddr *)&ss, &len) != 0)
        return;
~>    inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, host, sizeof host);
    printf("peer %s\n", host);
}
