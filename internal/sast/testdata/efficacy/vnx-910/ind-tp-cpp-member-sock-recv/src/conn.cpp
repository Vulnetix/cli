#include <sys/socket.h>
#include <unistd.h>

void Conn::drain()
{
    ::close(sock_);
    char buf[256];
~>    recv(sock_, buf, sizeof buf, 0);
}
