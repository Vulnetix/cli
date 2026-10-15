#include <stdint.h>
#include <sys/socket.h>

int send_frame(int sock, const char *payload, uint32_t len)
{
~>    if (send(sock, &len, sizeof(len), 0) < 0)
        return -1;
    return send(sock, payload, len, 0) < 0 ? -1 : 0;
}

int send_id(int sock, uint64_t id)
{
~>    return (int)sendto(sock, &id, sizeof id, 0, NULL, 0);
}
