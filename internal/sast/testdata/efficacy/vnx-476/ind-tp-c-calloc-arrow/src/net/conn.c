#include <stdlib.h>
#include "conn.h"

struct conn *conn_new(int fd, int flags)
{
    struct conn *c = calloc(1, sizeof(*c));

~>    c->fd = fd;
    return c;
}
