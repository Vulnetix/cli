#include <string.h>

int derive_all(int rounds)
{
    unsigned char key[32];
    for (int r = 0; r < rounds; r++) {
        memset(key, 0, sizeof key);
    }
    derive(key, sizeof key);
    memset(key, 0, sizeof key);
    key_init(key);
    unsigned char keybuf[16];
    memset(keybuf, 0, sizeof keybuf);
    __asm__ __volatile__("" : : "r"(keybuf) : "memory");
    return 0;
}
