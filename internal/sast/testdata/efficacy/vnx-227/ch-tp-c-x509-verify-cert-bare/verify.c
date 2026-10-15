#include <openssl/x509_vfy.h>

int check_peer(X509_STORE *store, X509 *cert)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);
~>    X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    return 1;
}
