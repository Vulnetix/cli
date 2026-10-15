#include <sys/stat.h>
#include <fcntl.h>

int install_helper(const char *path, int fd)
{
~>    if (chmod(path, 04755) < 0)
        return -1;
~>    if (fchmod(fd,
               S_ISGID | S_IRWXU | S_IRGRP | S_IXGRP) < 0)
        return -1;
    return 0;
}
