#include <sys/socket.h>
#include <unistd.h>

int pump(int fd)
{
    char buf[256];
    ssize_t n = ::recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
        return -1;
    buf[n] = '\0';

    char link[128];
    ssize_t r;
    if ((r = readlink("/tmp/x", link, sizeof link - 1)) < 0)
        return -1;
    link[r] = 0;
    return 0;
}

static int header_byte(const unsigned char *p)
{
    const unsigned char *cur = p + 4;
    return cur[-1];
}
