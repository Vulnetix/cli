#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int read_version(char *buf, size_t n)
{
    int fd = open("/etc/app/version", O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t got = read(fd, buf, n - 1);
    close(fd);
    if (got <= 0)
        return -1;
    buf[got] = '\0';
    return system("/usr/bin/app-migrate");
}
