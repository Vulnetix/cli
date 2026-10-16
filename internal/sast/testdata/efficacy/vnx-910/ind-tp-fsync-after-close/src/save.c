#include <unistd.h>

int save(int fd, const char *data, size_t n)
{
    write(fd, data, n);
    close(fd);
~>    return fsync(fd);
}
