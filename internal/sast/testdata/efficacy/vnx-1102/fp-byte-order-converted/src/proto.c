#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

int send_frame(int sock, uint32_t len)
{
    uint32_t wire = htonl(len);
    return (int)send(sock, &wire, sizeof(wire), 0);
}

int read_len(int fd, uint32_t *out)
{
    uint32_t n;
    if (read(fd, &n, sizeof(n)) != sizeof(n))
        return -1;
    *out = ntohl(n);
    return 0;
}

int send_port(int sock, uint16_t port)
{
    port = htons(port);
    return (int)send(sock, &port, sizeof port, 0);
}

void put64(FILE *fp, uint64_t v)
{
    v = htole64(v);
    fwrite(&v, sizeof(v), 1, fp);
}
