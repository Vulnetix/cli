#include <unistd.h>

int get_request(int fd)
{
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
~>    buf[n] = '\0';
    return process(buf);
}

int get_link(const char *p, char *out, size_t sz)
{
    int len;
    len = readlink(p, out, sz - 1);
~>    out[len] = 0;
    return len;
}
