#include <fcntl.h>
#include <unistd.h>

int write_all(const char *path, const char *buf, size_t n)
{
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0)
        return -1;
    if (write(fd, buf, n) < 0) {
~>        close(fd);
        goto out;
    }
    close(fd);
    return 0;
out:
    close(fd);
    return -1;
}
