#include <sys/socket.h>
#include <stdint.h>

int send_frame(int sock, const char *payload, uint32_t len)
{
~>    if (send(sock, &len, sizeof(len), 0) != sizeof(len))
        return -1;
    return send(sock, payload, len, 0);
}
