#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

int open_control(const char *path)
{
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    unlink(path);
~>    umask(0);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;
    listen(fd, 8);
    return fd;
}
