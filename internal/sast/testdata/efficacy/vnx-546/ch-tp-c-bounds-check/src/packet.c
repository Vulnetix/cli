#include <string.h>

void copy_payload(char *dst, const unsigned char *pkt, size_t len)
{
~>    /* XXX: no bounds check on len, dst is only 256 bytes */
    memcpy(dst, pkt + 4, len);
}
