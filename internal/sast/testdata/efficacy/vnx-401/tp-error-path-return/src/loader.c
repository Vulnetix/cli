#include <stdlib.h>
#include <unistd.h>

int load_block(int fd, size_t len, char **out_hash)
{
    char *buf = malloc(len);
    if (!buf)
        return -1;
    if (read(fd, buf, len) != (ssize_t)len)
~>        return -1;
    *out_hash = compute_hash(buf, len);
    free(buf);
    return 0;
}

int load_name(const char *src)
{
    char *copy = strdup(src);
    if (copy == NULL) {
        return -1;
    }
    if (strlen(copy) > MAX_NAME) {
        log_error("invalid name");
~>        return -2;
    }
    register_name(copy);
    return 0;
}
