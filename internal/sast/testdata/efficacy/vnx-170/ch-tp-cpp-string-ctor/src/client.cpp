#include <string>
#include <sys/socket.h>

std::string read_reply(int fd)
{
    char buf[512];
~>    ssize_t got = recv(fd, buf, sizeof buf, 0);
    if (got <= 0) {
        return "";
    }
    std::string reply(buf);
    return reply;
}
