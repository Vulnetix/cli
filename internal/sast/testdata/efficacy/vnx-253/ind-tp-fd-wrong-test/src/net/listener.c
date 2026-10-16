#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "listener.h"

int listener_open(const char *pidfile)
{
    int fd = open(pidfile, O_WRONLY | O_CREAT, 0644);
~>    if (!fd)
        return -1;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
~>    if (sock == NULL) {
        close(fd);
        return -1;
    }
    return sock;
}
