#include <stdio.h>
#include <unistd.h>

void flush_out(int fd, const char *b, size_t n)
{
    if (write(fd, b, n) < 0)
        perror("write");
    // if (sodium_init() < 0) printf("never");
}
