#include <sys/stat.h>

int is_loadable(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    if (!(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) return 0;
    if (st.st_size == 0) return 0;
    return S_ISREG(st.st_mode);
}

void copy_mode(int fd, const struct stat *src) {
    fchmod(fd, src->st_mode & 07777);
}
