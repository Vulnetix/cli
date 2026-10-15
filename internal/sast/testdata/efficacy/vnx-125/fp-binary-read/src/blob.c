#include <string.h>
#include <unistd.h>

void load(int fd, unsigned char *out)
{
    unsigned char hdr[16];
    ssize_t n = read(fd, hdr, sizeof(hdr));
    if (n != sizeof(hdr))
        return;
    memcpy(out, hdr, sizeof(hdr));
    printf("%zd bytes\n", n);
}
