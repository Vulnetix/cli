#include <cstdio>
#include <cstring>
#include <unistd.h>

struct header { unsigned magic; unsigned len; };

bool read_header(int fd, header *h)
{
    return read(fd, h, sizeof(*h)) == sizeof(*h);
}

void drain(int fd)
{
    char buf[512];
    while (read(fd, buf, sizeof(buf)) > 0) {}
}

void copy(char *dst, size_t n, const char *src)
{
    snprintf(dst, n, "%s", src);
    // strncpy(dst, src, n); was replaced by snprintf
    const char *msg = "never call strncpy(dst, src, n) without terminating";
    puts(msg);
}
