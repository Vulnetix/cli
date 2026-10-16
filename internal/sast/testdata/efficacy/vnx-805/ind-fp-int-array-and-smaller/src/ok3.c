#include <string.h>
#include <unistd.h>
void g(int fd)
{
    int vals[10];
    char b[64];
    memset(vals, 0, 40);
    read(fd, b, 32);
    memset(b, 0, 64);
}
