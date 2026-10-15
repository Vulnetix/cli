#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>

char *read_message(int sock)
{
    uint32_t raw;
    if (recv(sock, &raw, sizeof(raw), MSG_WAITALL) != sizeof(raw))
        return NULL;
    uint32_t len = ntohl(raw);
~>    char *msg = malloc(len + 1);
    if (!msg)
        return NULL;
    recv(sock, msg, len, MSG_WAITALL);
    msg[len] = '\0';
    return msg;
}
