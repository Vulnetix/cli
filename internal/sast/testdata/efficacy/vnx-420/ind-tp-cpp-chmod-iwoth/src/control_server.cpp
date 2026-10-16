#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

bool ControlServer::bindSocket(const std::string &path)
{
    fd_ = ::socket(AF_LOCAL, SOCK_STREAM, 0);
    sockaddr_un sa{};
    sa.sun_family = AF_LOCAL;
    std::strncpy(sa.sun_path, path.c_str(), sizeof(sa.sun_path) - 1);
    if (::bind(fd_, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) != 0)
        return false;
~>    ::chmod(path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    return ::listen(fd_, 16) == 0;
}
