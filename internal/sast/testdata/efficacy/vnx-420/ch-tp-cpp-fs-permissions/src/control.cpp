#include <filesystem>
#include <sys/socket.h>
#include <sys/un.h>

namespace fs = std::filesystem;

int open_control(const std::string &path) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    ::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
~>    fs::permissions(path, fs::perms::all);
~>    fs::permissions(path, fs::perms::others_write, fs::perm_options::add);
    return fd;
}
