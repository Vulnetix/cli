#include <stdint.h>
#include <sys/socket.h>

int read_message(int fd)
{
    unsigned char hdr[2];
    unsigned char body[1024];
    if (recv(fd, hdr, 2, MSG_WAITALL) != 2)
        return -1;
    uint16_t len = (hdr[0] << 8) | hdr[1];
~>    ssize_t got = recv(fd, body, len, MSG_WAITALL);
    return (int)got;
}
