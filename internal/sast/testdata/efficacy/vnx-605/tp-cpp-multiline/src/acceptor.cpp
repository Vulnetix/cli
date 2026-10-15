#include <sys/socket.h>

void Acceptor::configure(int fd) {
    const int enable = 1;
    if (::setsockopt(fd, SOL_SOCKET,
~>                     SO_REUSEPORT,
                     &enable, sizeof enable) < 0) {
        throw std::runtime_error("setsockopt");
    }
}
