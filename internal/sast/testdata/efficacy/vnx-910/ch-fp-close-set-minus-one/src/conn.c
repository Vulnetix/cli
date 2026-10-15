#include <unistd.h>

struct conn { int fd; };

void conn_reset(struct conn *c, int fd)
{
    close(fd);
    fd = -1;
    if (fd >= 0)
        write(fd, "x", 1);
    close(c->fd);
    c->fd = -1;
}
