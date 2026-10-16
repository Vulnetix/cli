#include <unistd.h>
#include <stdint.h>
#include <sys/eventfd.h>

void echo(int fd)
{
    char buf[512];
    char c = 'x';
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n > 0) write(fd, buf, n);
    write(fd, &c, 1);
}

void wake(int eventfd_fd)
{
    uint64_t one = 1;
    write(eventfd_fd, &one, sizeof(one));
}
