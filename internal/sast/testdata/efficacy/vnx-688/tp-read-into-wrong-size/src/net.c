#include <unistd.h>
#include <sys/socket.h>

int pump(int fd, int sock) {
    unsigned char header[8], body[4096];
~>    read(fd, header, sizeof(body));
~>    recv(sock, header, sizeof( body ), 0);
    return 0;
}
