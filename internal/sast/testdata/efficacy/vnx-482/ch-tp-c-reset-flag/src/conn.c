#include "conn.h"

void conn_reset(struct conn *c)
{
    c->state = CONN_IDLE;
~>    c->retries == 0;
    if (c->buf)
~>        c->buf[0] == '\0';
}
