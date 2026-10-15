#include <errno.h>
#include <stdio.h>
#include <string.h>

const char *describe(int err, char *buf, size_t len)
{
~>    char *msg = strerror_r(err, buf, len);
    return msg;
}

int describe_into(int err, char *buf, size_t len)
{
~>    if (strerror_r(err, buf, len) != 0)
        return -1;
    return 0;
}

void set_error(struct ctx *c)
{
~>    strerror_r(errno, c->errstr, sizeof(c->errstr));
    fprintf(stderr, "%s\n", c->errstr);
}
