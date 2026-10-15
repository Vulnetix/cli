#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

int read_frame(int fd)
{
    uint32_t raw;
    uint32_t len;
    read(fd, &raw, sizeof raw);
    len = ntohl(raw);
~>    unsigned char *payload = (unsigned char *)malloc(len);
    read(fd, payload, len);
    return 0;
}

int grow(char *p, int fd)
{
    unsigned short hdr;
    unsigned short size = ntohs(hdr);
~>    p = realloc(p, size + 1);
    return p != NULL;
}
