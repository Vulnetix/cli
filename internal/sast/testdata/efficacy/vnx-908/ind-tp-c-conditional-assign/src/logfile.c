#include <fcntl.h>
#include <unistd.h>

int open_log(const char *path)
{
    int fd;
    if (path != NULL) {
        fd = open(path, O_WRONLY | O_APPEND);
    }
~>    return fd;
}
