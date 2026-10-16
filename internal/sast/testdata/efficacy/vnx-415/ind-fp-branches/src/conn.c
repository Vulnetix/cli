#include <stdlib.h>

void conn_close(struct conn *c, int err)
{
    if (err) {
        free(c->rbuf);
    } else {
        flush(c);
        free(c->rbuf);
    }

    switch (c->mode) {
    case MODE_A:
        free(c->wbuf);
        break;
    case MODE_B:
        free(c->wbuf);
        break;
    }
}

int conn_fail(struct conn *c)
{
    free(c->name);
    return -1;
}

int conn_destroy(struct conn *c)
{
    free(c->name);
    free(c);
    return 0;
}
