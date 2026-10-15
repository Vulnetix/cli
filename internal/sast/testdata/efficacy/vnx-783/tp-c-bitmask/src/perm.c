#include <sys/stat.h>
#include <fcntl.h>

int world_writable(const struct stat *st)
{
~>    if (st->st_mode & S_IWOTH != 0) {
        return 1;
    }
    return 0;
}

int blocking(int flags)
{
~>    return flags & O_NONBLOCK == 0;
}
