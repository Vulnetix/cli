#include <stddef.h>

void wipe(unsigned char *key, size_t n, int *wiped)
{
    for (size_t i = 0; i < n; i++)
        key[i] = 0;
~>        *wiped = 1;
}
