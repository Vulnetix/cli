#include <stdio.h>
#include <sys/socket.h>

void greet(int sock)
{
    char msg[128];
    ssize_t n = recv(sock, msg, sizeof(msg) - 1, 0);
    if (n <= 0)
        return;
    msg[n] = '\0';
    printf("%s\n", msg);
}
