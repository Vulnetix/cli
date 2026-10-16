#include <sys/stat.h>
#include <unistd.h>

int slurp(int fd, char *buf, size_t n)
{
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    return read(fd, buf, n);
}
