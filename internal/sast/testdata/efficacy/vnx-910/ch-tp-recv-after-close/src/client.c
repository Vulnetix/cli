#include <sys/socket.h>
#include <unistd.h>

ssize_t fetch(int sock, char *buf, size_t n, int abort_early)
{
    if (abort_early)
        close(sock);
~>    return recv(sock, buf, n, 0);
}
