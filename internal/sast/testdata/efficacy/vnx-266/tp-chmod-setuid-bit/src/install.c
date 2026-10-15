#include <sys/stat.h>
#include <fcntl.h>

int install_helper(const char *dst, int fd)
{
~>    if (chmod(dst, 04755) != 0)
        return -1;
~>    fchmod(fd, S_ISUID | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
~>    return fchmodat(AT_FDCWD, dst, S_ISGID | 0755, 0);
}
