#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int write_pidfile(const char *path, int dirfd)
{
~>    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0)
        return -1;
    dprintf(fd, "%d\n", (int)getpid());
    close(fd);
~>    int lock = openat(dirfd, "app.lock", O_CREAT | O_EXCL | O_RDWR);
    return lock;
}
