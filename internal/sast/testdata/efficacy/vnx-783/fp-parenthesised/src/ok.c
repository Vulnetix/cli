#include <fcntl.h>
#include <stdlib.h>

int load(const char *path, char *buf, size_t sz, unsigned char *p)
{
    int fd;
    ssize_t n;
    if ((fd = open(path, O_RDONLY)) < 0)
        return -1;
    while ((n = read(fd, buf, sz)) > 0)
        consume(buf, n);
    if ((flags & O_NONBLOCK) == 0)
        return 1;
    if (fd == open_count(path) < limit)
        return 2;
    unsigned v = (p[0] << 8) + p[1];
    unsigned w = p[0] << (8 + shift);
    int ok = (status = check(x)) != 0;
    return v + w;
}
