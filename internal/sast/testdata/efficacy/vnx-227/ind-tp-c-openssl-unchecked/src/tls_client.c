#include <openssl/ssl.h>
#include <openssl/rand.h>

int connect_peer(SSL *ssl, unsigned char *session_key, size_t len)
{
    if (SSL_connect(ssl) != 1)
        return -1;
~>    SSL_get_verify_result(ssl);
~>    (void)RAND_bytes(session_key, (int)len);
    return 0;
}
