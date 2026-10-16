#include <sodium.h>
#include <syslog.h>
#include "keystore.h"

int keystore_open(struct keystore *ks)
{
~>    if (sodium_init() == -1) {
        syslog(LOG_ERR, "keystore: libsodium failed to initialise");
    }
    randombytes_buf(ks->salt, sizeof ks->salt);
    crypto_secretbox_keygen(ks->key);
    return 0;
}
