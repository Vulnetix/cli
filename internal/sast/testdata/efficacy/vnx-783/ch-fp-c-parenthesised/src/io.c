#include <fcntl.h>

int drain(const char *path, unsigned x, unsigned y, int flags)
{
    int fd;
    unsigned v = x << (8 + y);
    if ((fd = open(path, O_RDONLY)) < 0)
        return -1;
    if ((flags & O_APPEND) != 0)
        return 1;
    return (int)v;
}
