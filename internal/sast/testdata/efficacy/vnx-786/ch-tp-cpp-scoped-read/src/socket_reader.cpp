#include <unistd.h>
#include <sys/socket.h>
#include <string>

std::string SocketReader::next()
{
    char buf[512];
    ssize_t got = ::read(fd_, buf, sizeof(buf) - 1);
~>    buf[got] = '\0';
    return std::string(buf);
}

std::string SocketReader::peer_name()
{
    char name[256];
    int r = ::recv(fd_, name, sizeof name - 1, 0);
~>    name[r] = 0;
    return name;
}
