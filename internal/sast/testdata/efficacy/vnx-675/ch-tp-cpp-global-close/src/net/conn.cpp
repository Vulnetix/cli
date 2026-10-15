#include <unistd.h>

void Conn::shutdown()
{
    ::close(fd_);
    log("closed");
~>    ::close(fd_);
}
