#include <unistd.h>

int get(int fd)
{
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return 0;
}

int get2(int fd)
{
    char buf[64];
    int n;
    if ((n = read(fd, buf, sizeof buf - 1)) <= 0)
        return -1;
    buf[n] = 0;
    return n;
}
