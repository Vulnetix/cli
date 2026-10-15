#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int token_cache_flush(const char *cache, const char *buf, size_t n)
{
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s.new", cache);
    int fd = open(tmp,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                  0600);
    if (fd < 0)
        return -1;
    write(fd, buf, n);
    fsync(fd);
    close(fd);
    return rename(tmp, cache);
}
