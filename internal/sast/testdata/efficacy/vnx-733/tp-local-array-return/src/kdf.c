#include <string.h>

int derive(const unsigned char *salt, unsigned char *out) {
    unsigned char seed[32];
    char passphrase[256];
    get_passphrase(passphrase, sizeof passphrase);
    pbkdf(passphrase, salt, seed);
    expand(seed, out);
~>    memset(seed, 0, sizeof(seed));
~>    memset(passphrase, '\0', sizeof passphrase);
    return 0;
}

void wipe_pin(void) {
    char pin[8];
    read_pin(pin);
    use_pin(pin);
~>    memset(pin, 0x00, sizeof pin);
}
