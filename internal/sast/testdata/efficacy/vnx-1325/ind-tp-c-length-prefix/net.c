#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
char *read_frame(int fd)
{
    uint32_t raw, len;
    read(fd, &raw, 4);
    len = ntohl(raw);
~>    char *payload = malloc(len);
    read(fd, payload, len);
    return payload;
}
