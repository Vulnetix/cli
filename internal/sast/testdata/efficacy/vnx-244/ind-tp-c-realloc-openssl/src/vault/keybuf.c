#include <openssl/crypto.h>
#include <stdlib.h>
#include "keybuf.h"

int keybuf_grow(struct keybuf *kb, size_t n)
{
    if (n <= kb->cap)
        return 0;
~>    unsigned char *grown = realloc(kb->secret, n);
    if (grown == NULL)
        return -1;
    kb->secret = grown;
    kb->cap = n;
    return 0;
}

void tls_ctx_free(struct tls_ctx *ctx)
{
    X509_free(ctx->cert);
~>    OPENSSL_free(ctx->aes_key);
    OPENSSL_free(ctx->name);
    free(ctx);
}
