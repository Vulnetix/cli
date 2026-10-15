#include <stddef.h>
#include <unistd.h>
#include <errno.h>

int fill_buffer(int fd, char *buf, size_t cap)
{
    size_t got;

    got = read(fd, buf, cap);
~>    if (got < 0) {
        return -errno;
    }
    return (int)got;
}

int copy_header(const unsigned char *src, unsigned long len)
{
~>    if (len < 0 || src == NULL)
        return -1;
    return 0;
}
