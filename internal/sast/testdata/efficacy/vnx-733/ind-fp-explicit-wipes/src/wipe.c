#include <openssl/crypto.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

void drop_secret(char *secret, size_t n)
{
    explicit_bzero(secret, n);
    free(secret);
}

int use_passphrase(int (*fn)(const char *))
{
    char passphrase[256];
    int rc = fn(passphrase);
    OPENSSL_cleanse(passphrase, sizeof(passphrase));
    return rc;
}

void drop_seed(unsigned char *seed, size_t n)
{
    sodium_memzero(seed, n);
    free(seed);
}
