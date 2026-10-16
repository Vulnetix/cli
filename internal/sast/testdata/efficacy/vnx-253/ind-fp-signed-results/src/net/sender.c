#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "sender.h"

int sender_flush(int sock, const char *buf, size_t len)
{
    ssize_t sent = send(sock, buf, len, 0);
    if (sent < 0)
        return -1;
    int conn = accept(sock, NULL, NULL);
    if (conn == -1)
        return -1;
    char name[64];
    int w = snprintf(name, sizeof name, "peer-%d", conn);
    if (w < 0)
        return -1;
    return conn;
}
