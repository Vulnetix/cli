#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

long read_counter(const char *path)
{
    char buf[32];
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return strtol(buf, NULL, 10);
}
