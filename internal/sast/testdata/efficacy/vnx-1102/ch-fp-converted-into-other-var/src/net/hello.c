#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

int send_hello(int fd, uint16_t port, uint32_t session)
{
    uint16_t port_be = htons(port);
    uint32_t session_be = htonl(session);

    if (send(fd, &port_be, sizeof(port_be), 0) < 0)
        return -1;
    if (write(fd, &session_be, sizeof(session_be)) < 0)
        return -1;
    return 0;
}
