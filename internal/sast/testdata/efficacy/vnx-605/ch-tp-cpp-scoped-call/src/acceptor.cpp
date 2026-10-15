#include <sys/socket.h>
#include <netinet/in.h>
#include <stdexcept>

namespace net {

int open_acceptor(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    const int enable = 1;
~>    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) != 0) {
        throw std::runtime_error("reuseport");
    }
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    return fd;
}

}  // namespace net
