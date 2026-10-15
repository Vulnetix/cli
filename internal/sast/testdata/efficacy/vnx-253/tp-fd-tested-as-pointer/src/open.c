#include <fcntl.h>

int open_log(const char *path)
{
    int fd = open(path, O_WRONLY | O_APPEND);
~>    if (!fd)
        return -1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
~>    if (s == NULL) {
        return -1;
    }
    return fd;
}
