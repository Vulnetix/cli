#include <string.h>
#include <unistd.h>

void emit(int fd, char *buf, const char *in, char *out)
{
    size_t n = strlen(buf);
    buf[n] = '\n';
    write(fd, buf, n + 1);

    size_t m = strlen(in);
    out[m] = '\n';
}
