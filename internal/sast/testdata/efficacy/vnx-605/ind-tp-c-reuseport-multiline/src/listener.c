#include <sys/socket.h>
#include <netinet/in.h>

int open_listener(unsigned short port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd,
               SOL_SOCKET,
~>               SO_REUSEPORT,
               &one, sizeof(one));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    bind(fd, (struct sockaddr *)&a, sizeof(a));
    listen(fd, 128);
    return fd;
}
