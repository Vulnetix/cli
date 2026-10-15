#include <string.h>
#include <stdlib.h>
#include <openssl/crypto.h>

void wipe_all(unsigned char *key, size_t n, char *password) {
    explicit_bzero(key, n);
    free(key);
    OPENSSL_cleanse(password, strlen(password));
    free(password);
}

void wipe_win(char *secret, size_t n) {
    SecureZeroMemory(secret, n);
    free(secret);
}

void wipe_c11(char *token, size_t n) {
    memset_s(token, n, 0, n);
    free(token);
}
