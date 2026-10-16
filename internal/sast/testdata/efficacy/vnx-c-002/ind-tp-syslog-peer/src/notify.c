#include <syslog.h>
#include <stdio.h>
#include <sys/socket.h>

void handle_notify(int sock, FILE *audit)
{
    char peer_message[512];
    ssize_t n = recv(sock, peer_message, sizeof(peer_message) - 1, 0);
    if (n <= 0)
        return;
    peer_message[n] = '\0';
~>    syslog(LOG_ERR, peer_message);
~>    fprintf(audit, peer_message);
}
