#include <string.h>
#include <arpa/inet.h>

int copy_value(unsigned char out[64], const unsigned char *p)
{
    uint16_t len = ntohs(*(const uint16_t *)p);
    if (len > 64)
        return -1;
    memcpy(out, p + 2, len);
    return len;
}
