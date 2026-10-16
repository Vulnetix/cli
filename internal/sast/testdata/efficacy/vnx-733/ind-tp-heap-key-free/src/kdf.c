#include <stdlib.h>
#include <string.h>

int derive_and_encrypt(const unsigned char *salt, size_t salt_len,
                       const char *pass, unsigned char *out, size_t out_len,
                       int (*kdf)(const char *, const unsigned char *, size_t, unsigned char *, size_t),
                       int (*enc)(const unsigned char *, unsigned char *, size_t))
{
    size_t keylen = 32;
    unsigned char *key = malloc(keylen);
    if (key == NULL)
        return -1;
    if (kdf(pass, salt, salt_len, key, keylen) != 0) {
        free(key);
        return -1;
    }
    int rc = enc(key, out, out_len);
~>    memset(key, 0, keylen);
    free(key);
    return rc;
}
