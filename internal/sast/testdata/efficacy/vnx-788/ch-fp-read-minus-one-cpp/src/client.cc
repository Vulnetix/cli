#include <unistd.h>

int Client::poll()
{
    char reply[128];
    ssize_t n = ::read(fd_, reply, sizeof(reply) - 1);
    if (n <= 0)
        return -1;
    reply[n] = '\0';
    return handle(reply);
}
