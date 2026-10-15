#include <sys/socket.h>
#include <unistd.h>
#include <string>

class Client {
public:
    void stop(const std::string &bye)
    {
        ::close(sock_);
~>        ::send(sock_, bye.data(), bye.size(), 0);
    }

private:
    int sock_ = -1;
};
