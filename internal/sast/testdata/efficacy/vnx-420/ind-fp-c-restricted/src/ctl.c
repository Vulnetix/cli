#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

int open_control(const char *path)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    mode_t old = umask(0);
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    chmod(path, 0660);
    umask(old);
    chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    /* chmod(path, 0777) made it world-writable, fixed in 2.3 */
    return fd;
}
