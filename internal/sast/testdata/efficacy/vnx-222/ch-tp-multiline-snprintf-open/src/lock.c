#include <fcntl.h>
#include <limits.h>
#include <stdio.h>

int take_lock(const char *dir, const char *name)
{
    char path[64];
    int fd;

~>    snprintf(path, sizeof(path),
             "%s/%s.lock", dir, name);
    fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    return fd;
}
