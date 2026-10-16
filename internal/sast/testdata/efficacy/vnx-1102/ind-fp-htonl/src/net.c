#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>

int send_len(int sock, uint32_t len)
{
    uint32_t wire = htonl(len);
    return send(sock, &wire, sizeof(wire), 0);
}

int recv_len(int sock, uint32_t *out)
{
    uint32_t raw;
    if (recv(sock, &raw, sizeof(raw), 0) != sizeof(raw)) return -1;
    *out = ntohl(raw);
    return 0;
}
