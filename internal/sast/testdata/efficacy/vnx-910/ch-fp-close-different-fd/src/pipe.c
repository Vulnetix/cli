#include <unistd.h>

int spawn_writer(const char *msg, size_t len)
{
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    close(fds[0]);
    write(fds[1], msg, len);
    close(fds[1]);
    return 0;
}
