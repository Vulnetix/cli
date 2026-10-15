#include <openssl/ssl.h>
#include <openssl/rand.h>

/* SSL_get_verify_result(ssl); must be checked */
int connect_peer(SSL *ssl, unsigned char *nonce) {
    if (SSL_get_verify_result(ssl) != X509_V_OK)
        return -1;
    if (RAND_bytes(nonce, 16) != 1)
        return -1;
    int rc = X509_verify_cert(store_ctx);
    // RAND_bytes(nonce, 16);
    log_msg("call SSL_get_verify_result(ssl); before use");
    return rc;
}
