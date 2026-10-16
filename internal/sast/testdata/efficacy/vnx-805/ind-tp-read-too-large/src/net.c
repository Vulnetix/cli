#include <unistd.h>

int handle(int fd)
{
    char name[16];
~>    ssize_t n = read(fd, name, 32);
    if (n < 0)
        return -1;
    return (int)n;
}
