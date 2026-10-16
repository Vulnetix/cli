#include <winsock2.h>

SOCKET make_exclusive(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOL excl = TRUE;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&excl, sizeof(excl));
    BOOL reuse = FALSE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));
    return s;
}
