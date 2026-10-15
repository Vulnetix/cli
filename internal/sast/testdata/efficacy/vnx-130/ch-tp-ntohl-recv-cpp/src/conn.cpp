#include <arpa/inet.h>
#include <sys/socket.h>

void Conn::readBody(int fd, char *buf)
{
    auto n = ntohl(hdr_.length);
~>    ::recv(fd, buf, n, 0);
}
