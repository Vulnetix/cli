#include <fcntl.h>
#include <unistd.h>

static int lock_fd = -1;

static int set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

int runner_lock(const char *path)
{
    lock_fd = open(path, O_RDWR | O_CREAT, 0600);
    if (lock_fd < 0)
        return -1;
    return set_cloexec(lock_fd);
}

void runner_exec_job(char *const argv[])
{
    execvp(argv[0], argv);
}
