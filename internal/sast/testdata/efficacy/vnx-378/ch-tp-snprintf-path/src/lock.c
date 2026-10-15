#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int take_lock(const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.lock", name);
~>    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd < 0)
        return -1;
    return fd;
}
