#include <string.h>

void clear(void)
{
    char key[16];
    char iv[64];
~>    memset(key, 0, sizeof(iv));
    memset(iv, 0, sizeof iv);
}
