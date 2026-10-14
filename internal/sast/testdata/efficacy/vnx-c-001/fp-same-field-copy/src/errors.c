#include <string.h>

struct ctx {
    char errstr[128];
    int err;
};

void copy_error(struct ctx *dst, const struct ctx *src)
{
    dst->err = src->err;
    strcpy(dst->errstr, src->errstr);
}
