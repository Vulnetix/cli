#include <stdlib.h>
#include <unistd.h>

int load_block(int fd, size_t len)
{
    char *buf = malloc(len);
    if (!buf)
        return -1;
    if (read(fd, buf, len) != (ssize_t)len) {
        free(buf);
        return -1;
    }
    process(buf, len);
    free(buf);
    return 0;
}

int load_alt(int fd, size_t len)
{
    unsigned char *data = malloc(len);
    if (data == NULL) {
        perror("malloc");
        return -1;
    }
    memset(data, 0, len);
    if (read(fd, data, len) < 0)
        goto fail;
    free(data);
    return 0;
fail:
    free(data);
    return -1;
}
