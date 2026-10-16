#include <string.h>
#include <unistd.h>

struct hdr {
    unsigned magic;
    unsigned len;
};

int read_hdr(int fd, struct hdr *h, char *dst)
{
    char body[4096];
    read(fd, h, sizeof(struct hdr));
    read(fd, h, sizeof(*h));
    memset(dst, 0, sizeof(body));
    return read(fd, body, sizeof(body));
}
