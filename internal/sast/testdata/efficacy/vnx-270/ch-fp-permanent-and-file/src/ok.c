#include <fcntl.h>
#include <unistd.h>

int run_dropped(uid_t uid, char *const argv[])
{
    if (setresuid(uid, uid, uid) != 0)
        return -1;
    execv(argv[0], argv);
    return -1;
}

int open_as(uid_t uid, const char *path)
{
    seteuid(uid);
    int fd = open(path, O_RDONLY);
    seteuid(0);
    return fd;
}
