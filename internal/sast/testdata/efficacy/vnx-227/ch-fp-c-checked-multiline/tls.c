#include <openssl/ssl.h>

int check(SSL *ssl) {
    long rc =
        SSL_get_verify_result(ssl);
    if (RAND_bytes(buf, sizeof buf) != 1)
        return -1;
    return rc == X509_V_OK;
}
