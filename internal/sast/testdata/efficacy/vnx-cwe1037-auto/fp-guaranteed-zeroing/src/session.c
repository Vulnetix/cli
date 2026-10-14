#define __STDC_WANT_LIB_EXT1__ 1
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <sodium.h>

void session_destroy(struct session *s)
{
    explicit_bzero(s->session_key, sizeof(s->session_key));
    free(s);
}

void key_release(unsigned char *key, size_t len)
{
    memset_s(key, len, 0, len);
    free(key);
}

void ossl_release(unsigned char *secret, size_t len)
{
    OPENSSL_cleanse(secret, len);
    OPENSSL_free(secret);
}

int check_password(const char *input)
{
    char password[128];
    int ok;

    read_stored_password(password, sizeof password);
    ok = strcmp(input, password) == 0;
    sodium_memzero(password, sizeof(password));
    return ok;
}

void barrier_wipe(unsigned char *key, size_t len)
{
    memset(key, 0, len);
    __asm__ __volatile__("" : : "r"(key) : "memory");
    free(key);
}
