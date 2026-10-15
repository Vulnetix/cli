#include <string.h>

#define KEY_LEN 32

void derive(const unsigned char *salt, unsigned char *out)
{
    unsigned char key[KEY_LEN];
    memcpy(key, salt, KEY_LEN);
~>    key[KEY_LEN] = 0;
    memcpy(out, key, sizeof key);
}

void tag(void)
{
    static char label[8];
~>    label[8] = '\0';
}
