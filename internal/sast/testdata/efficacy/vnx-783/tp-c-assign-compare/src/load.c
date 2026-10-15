#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int load(const char *path, char *buf, size_t sz)
{
    int fd;
    ssize_t n;
    char *copy;

~>    if (fd = open(path, O_RDONLY) < 0) {
        return -1;
    }
~>    while (n = read(fd, buf, sz) > 0) {
        consume(buf, n);
    }
~>    if ((copy = malloc(sz) == NULL)) {
        return -1;
    }
    close(fd);
    return 0;
}
