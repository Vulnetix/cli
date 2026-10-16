#include <unistd.h>

int send_all(int fd, const char *buf, size_t n)
{
    if (write(fd, buf, n) < 0) {
        close(fd);
    }
~>    close(fd);
    return 0;
}
