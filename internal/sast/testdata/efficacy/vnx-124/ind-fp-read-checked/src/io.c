#include <unistd.h>

int read_all(int fd, char *buf, size_t cap)
{
    ssize_t n = read(fd, buf, cap - 1);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return (int)n;
}

void drain(int fd)
{
    char chunk[256];
    ssize_t r;
    while ((r = read(fd, chunk, sizeof chunk - 1)) > 0) {
        chunk[r] = 0;
        log_chunk(chunk);
    }
}
