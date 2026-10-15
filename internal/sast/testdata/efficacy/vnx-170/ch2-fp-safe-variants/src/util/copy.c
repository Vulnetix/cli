#include <string.h>
#include <unistd.h>
#include <stdlib.h>

void copy_name(char *dst, size_t dstlen, const char *src)
{
    strncpy(dst, src, dstlen - 1);
    dst[dstlen - 1] = '\0';
}

char *dup_str(const char *s)
{
    char *out = malloc(strlen(s) + 1);
    memcpy(out, s, strlen(s) + 1);
    return out;
}

int read_number(int fd)
{
    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return atoi(buf);
}

void forward(int in, int out)
{
    char chunk[4096];
    ssize_t n = read(in, chunk, sizeof(chunk));
    if (n > 0)
        write(out, chunk, n);
}
