#include <sys/socket.h>

#define BUFSZ 1024

int handle(int sock)
{
    char req[BUFSZ];
    int n = recv(sock, req, BUFSZ, 0);
    if (n < 0)
        return -1;
~>    req[n] = '\0';
    return parse_request(req);
}
