#include <unistd.h>

void child(int pipefd[2], const char *msg, size_t n)
{
    close(pipefd[0]);
    write(pipefd[1], msg, n);
    close(pipefd[1]);
}

void clear(struct conn *c)
{
    close(c->fd);
    c->fd = -1;
}
