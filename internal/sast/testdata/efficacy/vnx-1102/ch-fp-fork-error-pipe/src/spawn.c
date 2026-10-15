#include <errno.h>
#include <unistd.h>

pid_t spawn(const char *path, char *const argv[])
{
    int pfd[2];
    int err = 0;
    if (pipe(pfd) < 0)
        return -1;
    pid_t pid = fork();
    if (pid == 0) {
        close(pfd[0]);
        execv(path, argv);
        err = errno;
        write(pfd[1], &err, sizeof(err));
        _exit(127);
    }
    close(pfd[1]);
    if (read(pfd[0], &err, sizeof(err)) == sizeof(err))
        return -err;
    return pid;
}
