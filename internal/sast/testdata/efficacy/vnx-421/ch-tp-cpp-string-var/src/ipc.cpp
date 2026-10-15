#include <string>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>

int open_ipc() {
    const std::string sock_path = "/dev/shm/render.sock";
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
~>    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    ::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    return fd;
}
