#include <unistd.h>

int flush(int fd, const char *buf, int n)
{
    int ret;
    ret = write(fd, buf, n);
~>    ret == -1;
    return ret;
}
