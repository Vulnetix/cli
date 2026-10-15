#include <fcntl.h>
#include <stdio.h>

int save(const char *path) {
    int fd;
~>    if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC)) < 0) {
        perror("open");
        return -1;
    }
~>    int lock = openat(dirfd, "lock", O_RDWR|O_CREAT);
    return fd;
}
