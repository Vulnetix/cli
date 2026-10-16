#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static int write_all(int fd, const void *buf, size_t len);

int token_cache_flush(const char *cache_path, const unsigned char *blob, size_t len)
{
    char staging[512];
    int fd;

    snprintf(staging, sizeof staging, "%s.tmp", cache_path);
    fd = open(staging,
              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
              0644);
    if (fd < 0)
        return -1;
    if (write_all(fd, blob, len) != 0 || fsync(fd) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
~>    return rename(staging, cache_path);
}
