#include <fcntl.h>
#include <stdio.h>

int load(const char *path) {
    int fd;
~>    if (fd = open(path, O_RDONLY) < 0) {
        perror("open");
        return -1;
    }
    return fd;
}
