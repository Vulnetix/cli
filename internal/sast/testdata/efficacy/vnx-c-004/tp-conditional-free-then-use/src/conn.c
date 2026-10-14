#include <stdlib.h>

struct conn {
    int fd;
    char *rbuf;
};

int conn_step(struct conn *c, int err)
{
    if (err) {
        free(c);
    }
~>    return c->fd;
}

void conn_flush(struct conn *c, size_t n)
{
    if (n == 0)
        free(c->rbuf);
~>    c->rbuf[n] = '\0';
}
