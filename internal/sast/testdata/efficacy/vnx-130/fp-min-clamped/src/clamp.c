#include <string.h>
#include <arpa/inet.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

void clamp(char *dst, size_t cap, const unsigned char *src)
{
    size_t n = ntohs(*(const unsigned short *)src);
    n = MIN(n, cap);
    memcpy(dst, src + 2, n);
}
