#include <fcntl.h>
#include <unistd.h>

int save(const char *path, const char *data, size_t n)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    write(fd, data, n);
    close(fd);
~>    return fsync(fd);
}

void reply(struct conn *conn, const char *msg, size_t len)
{
    close(conn->fd);
    log_closed(conn);
~>    send(conn->fd, msg, len, 0);
}
