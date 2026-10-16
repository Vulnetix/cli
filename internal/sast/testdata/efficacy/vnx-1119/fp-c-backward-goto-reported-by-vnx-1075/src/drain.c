#include <errno.h>
#include <unistd.h>

/* A backward goto in a C file: VNX-1075 reports this line, so VNX-1119 does not. */
int drain(int fd, char *buf, size_t len)
{
    ssize_t n;
again:
    n = read(fd, buf, len);
    if (n < 0 && errno == EINTR)
        goto again;
    return (int)n;
}
