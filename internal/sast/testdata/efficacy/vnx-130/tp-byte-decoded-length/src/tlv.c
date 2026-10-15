#include <string.h>

void tlv(const unsigned char *p, unsigned char *out)
{
    unsigned int n = (p[0] << 8) | p[1];
~>    memmove(out, p + 2, n);
}
