#include <string.h>
#include <sys/socket.h>

int wait_for_ok(int sock)
{
    char reply[256];
~>    ssize_t got = recv(sock, reply, sizeof(reply), 0);
    if (got <= 0)
        return -1;
    if (strstr(reply, "+OK") == NULL)
        return -1;
    return 0;
}
