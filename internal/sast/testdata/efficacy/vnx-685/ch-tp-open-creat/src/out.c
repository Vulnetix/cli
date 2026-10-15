#include <fcntl.h>

int create(const char *path)
{
~>    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
    return fd;
}
