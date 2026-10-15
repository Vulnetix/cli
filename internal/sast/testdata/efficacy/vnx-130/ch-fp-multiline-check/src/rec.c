#include <string.h>
#include <arpa/inet.h>

int take(unsigned char *dst, const unsigned char *src, size_t avail)
{
    uint32_t rlen = ntohl(*(const uint32_t *)src);
    if (rlen + 4 > avail ||
        rlen > 4096) {
        return -1;
    }
    memcpy(dst, src + 4, rlen);
    return 0;
}
