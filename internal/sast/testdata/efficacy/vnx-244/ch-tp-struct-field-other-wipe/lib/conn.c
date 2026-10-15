#include <stdlib.h>
#include <string.h>

void conn_destroy(struct conn *c)
{
    memset(c->rbuf, 0, c->rbuf_len);
    free(c->rbuf);
~>    free(c->auth_password);
~>    free(c->client_secret);
    free(c);
}
