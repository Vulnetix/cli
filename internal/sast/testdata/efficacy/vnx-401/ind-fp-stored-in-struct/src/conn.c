#include <stdlib.h>
#include <string.h>

struct conn {
    char *rbuf;
    size_t rcap;
    int fd;
};

int conn_init(struct conn *c, int fd, size_t cap)
{
    char *b = calloc(1, cap);
    if (b == NULL)
        return -1;
    c->rbuf = b;
    c->rcap = cap;

    if (fd < 0)
        return -1;   /* caller runs conn_free(c), which frees rbuf */

    c->fd = fd;
    return 0;
}
