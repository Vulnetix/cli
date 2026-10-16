#include <sys/socket.h>
#include <unistd.h>

void handle_client(int sock)
{
    char req[1024];
    ssize_t n;

~>    n = recv(sock, req, 1024, 0);
    if (n <= 0) {
        close(sock);
        return;
    }
    dispatch(req, n);
}
