#include <winsock2.h>
#include <ws2tcpip.h>

SOCKET make_server(u_short port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOL reuse = TRUE;
~>    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));
    SOCKADDR_IN sa;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(port);
    bind(s, (SOCKADDR *)&sa, sizeof(sa));
    return s;
}
