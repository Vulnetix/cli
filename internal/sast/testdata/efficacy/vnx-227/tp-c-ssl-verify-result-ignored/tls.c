#include <openssl/ssl.h>
#include <openssl/rand.h>

int connect_peer(SSL *ssl, unsigned char *nonce) {
    if (SSL_connect(ssl) != 1)
        return -1;
~>    SSL_get_verify_result(ssl);
~>    RAND_bytes(nonce, 16);
~>    (void)X509_verify_cert(store_ctx);
    return 0;
}
