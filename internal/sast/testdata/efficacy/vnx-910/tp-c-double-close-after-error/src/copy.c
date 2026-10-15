#include <unistd.h>

int copy_out(int fd, const char *buf, size_t n)
{
    if (write(fd, buf, n) < 0) {
        perror("write");
        close(fd);
    }
~>    close(fd);
    return 0;
}
