#include <string.h>
#include <stdlib.h>
#include <openssl/crypto.h>

void done(char *password, unsigned char *key) {
    explicit_bzero(password, 64);
    free(password);
    OPENSSL_cleanse(key, 32);
    OPENSSL_free(key);
    memset_s(password, 64, 0, 64);
    SecureZeroMemory(key, 32);
}
