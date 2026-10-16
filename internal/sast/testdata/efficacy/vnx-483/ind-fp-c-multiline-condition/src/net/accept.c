#include "net.h"

int accept_ok(struct conn *c)
{
    if (c->fd >= 0 &&
        c->state == CONN_OPEN)
        c->accepted = 1;
    return c->accepted;
}
