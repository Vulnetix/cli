#include <fcntl.h>
#include <unistd.h>

void rotate(const char *path, const char *data, size_t n)
{
    int fd = open(path, O_WRONLY);
    close(fd);
    fd = open(path, O_WRONLY | O_APPEND);
    write(fd, data, n);
    close(fd);
}
