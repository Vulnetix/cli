#include <stdio.h>
#include <stdlib.h>

struct client {
    int fd;
    unsigned int csrf;
    char session_id[33];
    unsigned long authToken;
};

void accept_client(struct client *c, int fd)
{
    c->fd = fd;
~>    c->csrf = (unsigned int) lrand48();
~>    snprintf(c->session_id, sizeof(c->session_id), "%08lx%08lx", random(), random());
    c->authToken =
~>        ((unsigned long) rand() << 32) | (unsigned long) rand();
}
