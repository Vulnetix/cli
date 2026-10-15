#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int state_save(const char *path, const char *buf, size_t n) {
    char tmpname[] = "/var/lib/app/state.XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd == -1) return -1;
    write(fd, buf, n);
    close(fd);
    return rename(tmpname, path);
}

int token_save(const char *path, const char *buf, size_t n) {
    char staged[256];
    snprintf(staged, sizeof staged, "%s.tmp", path);
    int fd = open(staged, O_WRONLY | O_CREAT | O_EXCL, 0600);
    write(fd, buf, n);
    close(fd);
    return rename(staged, path);
}
