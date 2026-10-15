#include <stdlib.h>
#include "util.h"

void release_keys(struct keys *k, char *passphrase, size_t n)
{
    secure_zero(passphrase, n);
    free(passphrase);
    crypto_wipe(k->master_key, sizeof(k->master_key));
    free(k->master_key);
    OPENSSL_clear_free(k->priv_key, k->priv_key_len);
    sodium_free(k->session_key);
}
