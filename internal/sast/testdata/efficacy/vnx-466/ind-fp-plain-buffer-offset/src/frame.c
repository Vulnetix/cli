#include <stddef.h>

/* return strchr(buf, '=') + 1 would be wrong if the separator is missing. */
const unsigned char *frame_payload(const unsigned char *buf, size_t hdr)
{
    return buf + hdr + 1;
}
