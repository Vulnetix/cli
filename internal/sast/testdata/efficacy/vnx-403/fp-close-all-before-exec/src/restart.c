#include <fcntl.h>
#include <unistd.h>

int listen_fd;

void setup(const char *path)
{
    listen_fd = open(path, O_RDWR);
}

void restart(char **argv)
{
    for (int j = 3; j < (int)sysconf(_SC_OPEN_MAX); j++) {
        if (fcntl(j, F_GETFD) != -1) close(j);
    }
    execve(argv[0], argv, environ);
}
