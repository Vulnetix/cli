#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

int start_daemon(void)
{
    struct sockaddr_un sa;
    int fd = socket(AF_LOCAL, SOCK_STREAM, 0);
~>  umask(0);
    sa.sun_family = AF_LOCAL;
    strcpy(sa.sun_path, "/run/mydaemon.sock");
    bind(fd, (struct sockaddr *)&sa, sizeof(sa));
    return fd;
}
