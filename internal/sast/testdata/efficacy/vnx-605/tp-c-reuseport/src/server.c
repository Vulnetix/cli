#include <sys/socket.h>
#include <netinet/in.h>

int open_listener(unsigned short port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
~>    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    return fd;
}
