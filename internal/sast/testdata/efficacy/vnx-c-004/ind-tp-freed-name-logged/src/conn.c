#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct conn {
    int fd;
    char *peer_name;
};

void conn_close(struct conn *c)
{
    close(c->fd);
    free(c->peer_name);
~>    fprintf(stderr, "closed connection to %s\n", c->peer_name);
    free(c);
}
