#include <stdio.h>

void dump(void)
{
    unsigned char key[16];
    size_t i;
~>    for (i = 0; i <= sizeof(key); i++)
        printf("%02x", key[i]);
    int codes[8];
~>    for (size_t j = 0; j <= sizeof(codes) / sizeof(codes[0]); j++) {
        printf("%d\n", codes[j]);
    }
}
