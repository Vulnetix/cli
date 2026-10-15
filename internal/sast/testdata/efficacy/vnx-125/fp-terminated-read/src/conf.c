#include <string.h>
#include <unistd.h>

void load(int fd)
{
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0)
        return;
    buf[n] = '\0';
    printf("config: %s\n", buf);
}

void load2(int fd)
{
    char line[64];
    ssize_t r = read(fd, line, sizeof(line));
    if (r <= 0)
        return;
    line[r - 1] = 0;
    puts(line);
}
