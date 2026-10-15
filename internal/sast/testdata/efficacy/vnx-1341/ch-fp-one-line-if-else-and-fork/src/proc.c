#include <stdlib.h>
#include <unistd.h>

void drop(char *buf, int owned)
{
    if (owned) free(buf);
    else free(buf);
}

int spawn(int fd)
{
    pid_t pid = fork();
    if (pid == 0) {
        close(fd);
        execl("/bin/true", "true", (char *)NULL);
        _exit(127);
    }
    close(fd);
    return pid;
}
