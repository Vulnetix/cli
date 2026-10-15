#include <stdio.h>
#include <sys/socket.h>

int set_reuse(int fd)
{
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        perror("setsockopt SO_REUSEPORT");
        return -1;
    }
    return 0;
}
