#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int notify(int sock, const char *msg, int quiet)
{
    if (quiet)
        close(sock);
~>    return (int)send(sock,
                     msg,
                     strlen(msg),
                     0);
}
