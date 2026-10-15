#include <winsock2.h>
#include <stdio.h>

int net_open(const char *host, unsigned short port)
{
    WSADATA wsa;
~>    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    return connect_to(s, host, port);
}
