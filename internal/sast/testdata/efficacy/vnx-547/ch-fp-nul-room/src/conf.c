#include <unistd.h>

int load(int fd)
{
    char buf[256];
    ssize_t n = read(fd, buf, 255);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return parse(buf);
}
