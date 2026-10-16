#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int install_helper(const char *dst, int fd)
{
    if (chown(dst, 0, 0) != 0)
        return -1;
~>    if (chmod(dst, 04755) != 0)
        return -1;
~>    return fchmod(fd, S_ISGID | S_IRWXU | S_IRGRP | S_IXGRP);
}
