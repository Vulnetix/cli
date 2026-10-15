#include <unistd.h>

void handle(int fd)
{
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0)
        return;
    buf[n] = '\0';
}

void link_target(const char *path)
{
    char target[256];
    ssize_t len = readlink(path, target, sizeof(target) - 1);
    if (len == -1) {
        perror("readlink");
        return;
    }
    target[len] = 0;
}

void loop(int fd)
{
    char b[64];
    ssize_t r;
    while ((r = read(fd, b, sizeof b - 1)) > 0) {
        b[r] = 0;
    }
}
