#include <cerrno>
#include <unistd.h>

ssize_t Conn::read_all(char *buf, size_t n)
{
retry:
    ssize_t r = ::read(fd_, buf, n);
    if (r < 0 && errno == EINTR)
~>        goto retry;
    return r;
}
