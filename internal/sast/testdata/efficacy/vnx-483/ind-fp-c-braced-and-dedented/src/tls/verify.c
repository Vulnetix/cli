#include "tls.h"

int verify(struct ctx *ctx, int *b)
{
    if (ctx->a < 0)
        b[0] = -1;
    b[1] = 0;

    if (ctx->c > 0) {
        b[2] = 1;
        b[3] = 1;
    }

    if (ctx->d)
        b[4] = 2;

    b[5] = 3;
    return 0;
}
