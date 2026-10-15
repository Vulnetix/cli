#include <sys/socket.h>
#include <unistd.h>

int pump(int s, char *buf, size_t sz)
{
    ssize_t got;
    size_t total = 0;
    got = recv(s, buf, sz, 0);
    if (got < 0)
        return -1;
    total += (size_t) got;
    size_t n = fread(buf, 1, sz, stdin);
    if (n < sz)
        return 0;
    return (int) total;
}
