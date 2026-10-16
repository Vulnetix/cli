#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int pidfile_read(const char *path)
{
    char buf[16];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
~>    if (read(fd, buf, sizeof(buf)) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return atoi(buf);
}
