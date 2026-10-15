#include <fcntl.h>

int create(const char *path, int dirfd) {
~>    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
~>    int fd2 = openat(dirfd, "lock", O_CREAT | O_EXCL);
    return fd + fd2;
}
