#include <errno.h>
#include <string.h>

struct conn { int fd; char errstr[128]; };

void conn_set_error(struct conn *c)
{
~>    strerror_r(errno, c->errstr, sizeof(c->errstr));
}
