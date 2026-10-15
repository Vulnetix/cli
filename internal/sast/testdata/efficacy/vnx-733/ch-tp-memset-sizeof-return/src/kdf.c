#include <string.h>

int derive(const char *pass, unsigned char *out) {
    unsigned char key[32];
    pbkdf2(pass, key, sizeof key);
    memcpy(out, key, sizeof key);
~>    memset(key, 0, sizeof key);
    return 0;
}
