#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>

int read_reply(int fd, char *buf, size_t cap)
{
    uint32_t n;
~>    if (read(fd, &n, sizeof(n)) != sizeof(n))
        return -1;
    if (n > cap)
        return -1;
    return (int)read(fd, buf, n);
}

int recv_count(int sock)
{
    int32_t count;
~>    recv(sock, &count, sizeof(int32_t), MSG_WAITALL);
    return count;
}

void load(FILE *in, double *score)
{
~>    fread(score, sizeof(double), 1, in);
}
