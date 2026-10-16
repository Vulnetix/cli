#include <string.h>

struct hdr { int x; };

void p(char *dst, struct hdr *h, int fd)
{
    char other[64];
    memset(dst, 0, sizeof(struct hdr));
    memset(h, 0, sizeof(*h));
    read(fd, dst, sizeof(*h));
}
