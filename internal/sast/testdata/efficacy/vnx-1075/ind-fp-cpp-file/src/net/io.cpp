#include <cerrno>
ssize_t read_all(int fd, char *buf, size_t len)
{
    ssize_t n;
retry:
    n = read(fd, buf, len);
    if (n < 0 && errno == EINTR)
        goto retry;
    return n;
}
