#include <unistd.h>

int spawn(const char *path, char *const argv[])
{
~>    pid_t pid = vfork();
    if (pid == 0) {
        execv(path, argv);
        _exit(127);
    }
    return (int)pid;
}
