#include <fcntl.h>
#include <string.h>

int io(char *buf, size_t n, const char *p) {
    memset(buf, 0, sizeof buf);
    memset(buf, '\0', n);
    memset(buf, 0, 0);
    int fd = open(p, O_CREAT | O_WRONLY, 0644);
    int fd2 = open(p, O_RDONLY);
    int fd3 = openat(AT_FDCWD, p, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR | S_IWUSR);
    return fd + fd2 + fd3;
}
