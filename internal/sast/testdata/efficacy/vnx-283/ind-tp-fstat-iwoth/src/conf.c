#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int conf_open_trusted(const char *path)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat sb;

    if (fd < 0)
        return -1;
    if (fstat(fd, &sb) != 0)
        goto bad;
~>    if ((sb.st_mode & S_IWOTH) != 0 ||
        (sb.st_mode & S_IWGRP) != 0)
        goto bad;
    return fd;
bad:
    close(fd);
    return -1;
}
