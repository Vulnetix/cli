#include <stddef.h>
#include <string.h>
#include <stdint.h>

int parse_header(const unsigned char *buf, size_t len)
{
    size_t remaining = len - 4;
~>    if (remaining < 0) {
        return -1;
    }
    return buf[remaining];
}

int read_name(const char *name)
{
    uint32_t want;
    want = (uint32_t)name[0] - 8;
~>    if (want < 0 || strlen(name) > 255)
        return -1;
~>    if (strlen(name) < 0)
        return -2;
    return 0;
}

int copy_out(char *dst, const char *src)
{
    unsigned int n = 0;
    while (src[n]) n++;
~>    if (0 > sizeof(dst) || n < 0)
        return -1;
    memcpy(dst, src, n);
    return (int)n;
}
