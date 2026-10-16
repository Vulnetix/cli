#include <openssl/crypto.h>
#include <string.h>

void done(char *key, size_t key_len)
{
    char password[64];
    unsigned char master[32];
    prompt(password);
    explicit_bzero(password, sizeof password);
    OPENSSL_cleanse(master, sizeof master);
    sodium_memzero(key, key_len);
    free(key);
}
