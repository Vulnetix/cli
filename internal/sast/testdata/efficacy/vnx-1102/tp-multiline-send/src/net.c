#include <stdint.h>
#include <sys/socket.h>

int announce(int sock, uint16_t port)
{
~>    ssize_t r = send(sock,
                     &port,
                     sizeof(port), 0);
    return r == sizeof(port) ? 0 : -1;
}
