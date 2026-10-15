#ifndef CONN_H
#define CONN_H

struct conn {
    int fd;
    char *host;
    unsigned int flags;
};

static inline int conn_fd(const struct conn *c)
{
    return c->fd;
}

#endif
