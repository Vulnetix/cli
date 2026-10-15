#include <stdint.h>
#include <string.h>
#include <unistd.h>

static void put_u32_be(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

int write_frame(int fd, const char *msg)
{
    unsigned char hdr[4];
    size_t len = strlen(msg);

    put_u32_be(hdr, (uint32_t)len);
    if (write(fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
        return -1;
    if (write(fd, msg, len) != (ssize_t)len)
        return -1;
    return 0;
}
