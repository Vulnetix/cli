#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

int read_frame(int fd, struct frame *f)
{
    uint32_t hdr;
    if (recv_all(fd, &hdr, sizeof hdr) < 0)
        return -1;
    uint32_t body_len = ntohl(hdr);
    if (body_len == 0)
        return 0;
~>    f->body = (unsigned char *)realloc(f->body,
                                       body_len + 1);
    return recv_all(fd, f->body, body_len);
}
