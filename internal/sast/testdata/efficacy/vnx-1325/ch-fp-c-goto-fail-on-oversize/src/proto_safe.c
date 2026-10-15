#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAX_MSG 65536

char *read_message_safe(int sock)
{
    uint32_t raw;
    char *msg = NULL;
    if (recv(sock, &raw, sizeof(raw), MSG_WAITALL) != sizeof(raw))
        goto fail;
    uint32_t len = ntohl(raw);
    if (len > MAX_MSG)
        goto fail;
    msg = malloc(len + 1);
    return msg;
fail:
    return NULL;
}
