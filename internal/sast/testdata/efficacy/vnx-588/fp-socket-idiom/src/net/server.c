#include <netinet/in.h>
#include <sys/socket.h>

int listen_on(int fd, int port)
{
    struct sockaddr_in addr;
    struct sockaddr_storage ss;
    addr.sin_port = htons(port);
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    getsockname(fd, (struct sockaddr *)&ss, NULL);
    return 0;
}
