#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int cmdline_length(const char *path)
{
    char buf[256];
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0)
        return -1;
~>    size_t len = strlen(buf);
    return (int)len;
}
