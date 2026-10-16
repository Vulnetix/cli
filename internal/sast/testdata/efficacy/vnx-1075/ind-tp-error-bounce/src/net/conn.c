#include <sys/socket.h>
#include <errno.h>

int open_conn(const char *host)
{
    int fd;
try_again:
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        goto socket_err;
    if (connect_to(fd, host) < 0) {
        close(fd);
        goto socket_err;
    }
    return fd;
socket_err:
    if (errno == EAGAIN) {
        usleep(1000);
~>        goto try_again;
    }
    return -1;
}
