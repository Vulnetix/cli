#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int read_record(int fd, size_t len, int (*handle)(const char *, size_t))
{
    char *buf = malloc(len);
    if (!buf)
        return -1;

    ssize_t got = read(fd, buf, len);
    if (got != (ssize_t)len) {
        free(buf);
        return -1;
    }

    int rc = handle(buf, len);
    free(buf);
    return rc;
}
