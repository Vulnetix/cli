#include <winsock2.h>
#include <ws2tcpip.h>

SOCKET make_listener(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOL reuse = TRUE;
~>    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));
    return s;
}
