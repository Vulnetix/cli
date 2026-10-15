#include <fcntl.h>
#include <unistd.h>

void rotate(int *fdp, const char *path)
{
    int fd = *fdp;
    close(fd);
    fd = open(path, O_WRONLY | O_APPEND);
    write(fd, "\n", 1);
    *fdp = fd;
}

void shutdown_conn(struct conn *c)
{
    close(c->fd);
    c->fd = -1;
    if (c->fd >= 0)
        close(c->fd);
}
