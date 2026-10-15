#include <sys/types.h>
#include <unistd.h>

int classify(int fd, char *buf, size_t cap, int x, int y)
{
    ssize_t got = read(fd, buf, cap);
    if (got < 0)
        return -1;
    if (x >= 0 && x <= 0)
        return 0;
    if (x == 1 && y == 2)
        return 1;
    if (x < 10 && x > 5)
        return 2;
    return 3;
}
