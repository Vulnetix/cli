#include <unistd.h>

int request(int fd)
{
    char req[1024];
    ssize_t got = read(fd, req, sizeof(req) - 1);
    if (got < 0)
        return -1;
    req[got] = '\0';
    return 0;
}

int whole(int fd)
{
    char blob[64];
    ssize_t got = read(fd, blob, sizeof blob);
    return consume(blob, got);
}
