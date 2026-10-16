#include <unistd.h>

int handle(int fd)
{
    char buf[512];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    return (int)n;
}
