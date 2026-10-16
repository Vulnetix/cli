#include <unistd.h>
#include <sys/socket.h>

int read_reply(int sock, char *buf, int len)
{
    int n;
    send(sock, "PING", 4, 0);
~>    close(sock);
    n = recv(sock, buf, len - 1, 0);
    return n;
}
