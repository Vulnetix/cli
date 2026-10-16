#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * SO_REUSEADDR only lets us rebind while old connections sit in TIME_WAIT.
 * We deliberately do not use SO_REUSEPORT here.
 */
int httpd_listen(unsigned short port)
{
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    int on = 1;
    int reuseport = 0;
    socklen_t len = sizeof(reuseport);
    struct sockaddr_in6 sa;

    if (fd < 0)
        return -1;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

#ifdef SO_REUSEPORT
    /* Log whether the platform default turned it on. */
    getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, &len);
#endif

    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = in6addr_any;
    sa.sin6_port = htons(port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return listen(fd, 64) == 0 ? fd : -1;
}
