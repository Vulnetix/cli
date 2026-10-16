#include <stdlib.h>
#include <string.h>

struct cipher_ctx {
    unsigned char key[32];
    unsigned char iv[16];
};

void cipher_ctx_free(struct cipher_ctx *ctx)
{
    if (ctx == NULL)
        return;
    memset(ctx->key, 0, sizeof(ctx->key));
    free(ctx);
}

void reset_password(char *password, size_t n)
{
    memset(password, 0, n);
    return;
}
