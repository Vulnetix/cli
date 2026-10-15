#include <stdio.h>
#include <sys/socket.h>

void report_options(int fd)
{
    int one = 1, v = 0;
    socklen_t len = sizeof(v);
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, &len);
    printf("reuseport=%d\n", v);
}
