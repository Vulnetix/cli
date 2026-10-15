#include <winsock2.h>

void drop(SOCKET s)
{
~>    closesocket(s);
    shutdown(s, SD_BOTH);
}
