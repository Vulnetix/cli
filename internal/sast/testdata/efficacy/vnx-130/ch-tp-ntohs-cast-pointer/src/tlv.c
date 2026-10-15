#include <string.h>
#include <arpa/inet.h>

void copy_value(unsigned char *out, const unsigned char *p)
{
    uint16_t len = ntohs(*(const uint16_t *)p);
~>    memcpy(out, p + 2, len);
}
