#include <unistd.h>

void finish(int fd, int keep, const char *buf, size_t n)
{
    if (!keep) {
        close(fd);
    } else {
        write(fd, buf, n);
    }
}

void end_one(int fd)
{
    close(fd);
}

void start_two(int fd, const char *buf)
{
    write(fd, buf, 1);
}
