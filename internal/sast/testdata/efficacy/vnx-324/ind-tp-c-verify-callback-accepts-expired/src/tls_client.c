#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>

static int verify_cb(int preverify_ok, X509_STORE_CTX *ctx)
{
    int err = X509_STORE_CTX_get_error(ctx);

    if (preverify_ok) {
        return 1;
    }
~>    if (err == X509_V_ERR_CERT_HAS_EXPIRED) {
        fprintf(stderr, "warning: peer certificate expired, accepting\n");
        return 1;
    }
    return 0;
}

SSL_CTX *make_client_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);
    return ctx;
}
