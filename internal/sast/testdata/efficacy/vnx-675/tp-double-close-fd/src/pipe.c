#include <unistd.h>

void spawn(int fds[2])
{
    int rd = fds[0];
    close(rd);
    if (dup2(fds[1], 1) < 0)
        perror("dup2");
~>    close(rd);
    close(fds[1]);
~>    close(fds[1]);
}
