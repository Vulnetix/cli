#include <unistd.h>
#include <sys/socket.h>

class Conn {
public:
    void hangup();
private:
    int fd_;
};

void Conn::hangup()
{
~>    ::close(fd_);
    const char bye[] = "bye\n";
    ::send(fd_, bye, sizeof bye - 1, 0);
}
