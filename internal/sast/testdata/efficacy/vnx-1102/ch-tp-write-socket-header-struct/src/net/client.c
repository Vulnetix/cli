#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

struct frame_header {
    uint16_t type;
    uint32_t length;
};

int send_frame(int sock, uint16_t type, const void *payload, uint32_t len)
{
    struct frame_header hdr;
    hdr.type = type;
    hdr.length = len;
~>    if (write(sock, &hdr, sizeof(struct frame_header)) < 0)
        return -1;
    return (int)write(sock, payload, len);
}

int read_count(int sock, uint64_t *count)
{
~>    return recv(sock, count, sizeof(*count), MSG_WAITALL) == sizeof(*count) ? 0 : -1;
}
