#include <sys/socket.h>
#include <stdio.h>

void read_banner(int sock)
{
    char buf[512];
    int got = recv(sock, buf, sizeof(buf) - 1, 0);
~>    buf[got] = '\0';
    printf("server: %s\n", buf);
}
