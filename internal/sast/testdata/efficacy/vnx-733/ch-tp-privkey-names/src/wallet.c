#include <stdlib.h>
#include <string.h>

void wallet_close(struct wallet *w) {
    char *passphrase = w->passphrase;
    unsigned char *privkey = w->priv;
~>    memset(passphrase, 0, strlen(passphrase));
    free(passphrase);
~>    memset(privkey, 0x00, 32);
    free(privkey);
    free(w);
}
