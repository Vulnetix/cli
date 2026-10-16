#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <sodium.h>
#include "session.h"

void session_logout(struct session *s)
{
    size_t n = strlen(s->password);
    explicit_bzero(s->password, n);
    free(s->password);

    OPENSSL_cleanse(s->session_key, SESSION_KEY_LEN);
    OPENSSL_free(s->session_key);

    sodium_memzero(s->master_key, MASTER_KEY_LEN);
    free(s->master_key);
}

void keys_release(struct keys *k)
{
    sodium_free(k->private_key);
    OPENSSL_clear_free(k->enc_key, k->enc_key_len);
}
