#include <unistd.h>

int handle(int fd)
{
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
~>    buf[n] = '\0';
    return (int)n;
}
