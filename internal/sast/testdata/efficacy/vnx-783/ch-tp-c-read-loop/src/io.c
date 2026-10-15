#include <unistd.h>
#include <fcntl.h>

int drain(const char *path, char *buf, size_t sz)
{
    int fd;
    ssize_t n;
~>    if (fd = open(path, O_RDONLY) < 0)
        return -1;
~>    while (n = read(fd, buf, sz) > 0) {
        buf[0] = 0;
    }
    return 0;
}
