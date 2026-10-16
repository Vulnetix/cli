#include <arpa/inet.h>
#include <stdlib.h>

int allowed(const char *addr_text, const char *port_text) {
    struct in_addr a;
    char *end;
~>  long port = strtol(port_text, &end, 0);
~>  if (inet_aton(addr_text, &a) == 0) return 0;
    return port > 1024 && (ntohl(a.s_addr) >> 24) == 10;
}
