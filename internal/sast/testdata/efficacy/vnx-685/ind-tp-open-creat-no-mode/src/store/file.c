#include <fcntl.h>
#include <unistd.h>

int open_journal(const char *path, int dirfd, const char *name)
{
~>    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
        return -1;
    }
~>    int lock = openat(dirfd, name, O_RDWR | O_CREAT | O_EXCL);
    close(lock);
    return fd;
}
