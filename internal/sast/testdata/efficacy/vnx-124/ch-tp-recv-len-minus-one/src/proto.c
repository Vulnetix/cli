#include <sys/socket.h>

void get_cmd(int sock, char *buf, size_t size)
{
    ssize_t r = recv(sock, buf, size, 0);
~>    buf[r] = '\0';
}
