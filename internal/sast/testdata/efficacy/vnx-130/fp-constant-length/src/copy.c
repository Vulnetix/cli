#include <string.h>
#include <arpa/inet.h>

void copy(unsigned char *dst, const unsigned char *src, unsigned short port)
{
    unsigned short net = htons(port);
    memcpy(dst, &net, sizeof(net));
    memcpy(dst + 2, src, 16);
    unsigned int v = ntohl(*(const unsigned int *)src);
    store(v);
    memcpy(dst + 4, &v, sizeof v);
}
