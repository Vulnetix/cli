#include <sys/stat.h>
#include <unistd.h>

int load(int fd, char *buf, size_t n)
{
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    for (int i = 0; i < 3; i++) {
        if (i == 2) {
            close(fd);
            break;
        }
        read(fd, buf, n);
    }
    return (int)read(fd, buf, n);
}

int with_cleanup(int fd, char *buf, size_t n)
{
    if (read(fd, buf, n) < 0) {
        close(fd);
        goto fail;
    }
    write(fd, buf, n);
    return 0;
fail:
    return -1;
}
