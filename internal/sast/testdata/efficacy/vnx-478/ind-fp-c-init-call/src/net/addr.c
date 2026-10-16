#include <string.h>
#include "addr.h"

int addr_port(int family, const struct sockaddr_storage *ss)
{
    struct portinfo info;

    portinfo_init(&info);
    switch (family) {
    case AF_INET:  info.port = in4_port(ss); break;
    case AF_INET6: info.port = in6_port(ss); break;
    }
    return info.port;
}
