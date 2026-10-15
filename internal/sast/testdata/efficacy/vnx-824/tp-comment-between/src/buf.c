#include <string.h>

void fill(void)
{
    unsigned char *out;

    /* out = malloc(16); forgotten */
~>    memset(out, 0, 16);
}
