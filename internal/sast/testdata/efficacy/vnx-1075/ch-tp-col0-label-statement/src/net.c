#include <errno.h>
#include <unistd.h>

ssize_t write_all(int fd, const char *buf, size_t len)
{
    size_t done = 0;
    ssize_t n;
again: n = write(fd, buf + done, len - done);
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN)
~>            goto again;
        return -1;
    }
    done += (size_t)n;
~>    if (done < len) goto again;
    return (ssize_t)done;
}
