#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

int open_as_user(const char *path, uid_t uid)
{
    int fd;
    if (seteuid(uid) != 0)
        return -1;
    fd = open(path, O_RDONLY);
    if (seteuid(0) != 0)
        _exit(1);
    return fd;
}
