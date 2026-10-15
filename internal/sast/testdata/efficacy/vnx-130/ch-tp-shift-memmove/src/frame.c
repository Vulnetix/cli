#include <string.h>

void unframe(unsigned char *dst, const unsigned char *pkt)
{
    size_t len = (pkt[0] << 8) | pkt[1];
~>    memmove(dst,
            pkt + 2,
            len);
}
