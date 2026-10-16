#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>

int load(const char *path, const struct stat *st, const uint8_t *p) {
    int fd;
    if ((fd = open(path, O_RDONLY)) < 0) return -1;
    if ((st->st_mode & S_IWOTH) == 0) return 0;
    uint16_t v = (p[0] << 8) + p[1];
    return fd + v;
}
