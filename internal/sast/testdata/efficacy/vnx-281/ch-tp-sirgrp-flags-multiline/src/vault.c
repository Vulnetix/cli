#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int vault_commit(const char *vault_path, const void *blob, size_t len)
{
    char scratch[PATH_MAX];
    snprintf(scratch, sizeof scratch, "%s.partial", vault_path);
    int fd = open(scratch, O_CREAT | O_WRONLY | O_TRUNC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0)
        return -1;
    if (write(fd, blob, len) != (ssize_t)len) {
        close(fd);
        return -1;
    }
    close(fd);
~>    if (rename(scratch,
               vault_path) < 0)
        return -1;
    return 0;
}
