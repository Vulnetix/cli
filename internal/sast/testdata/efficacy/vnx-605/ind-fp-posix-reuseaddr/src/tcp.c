#include <sys/socket.h>

int tcp_listen(int fd)
{
    int on = 1;
    /* SO_REUSEADDR only skips TIME_WAIT on POSIX */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
        return -1;
    return listen(fd, 64);
}
