#include <stdlib.h>
#include <arpa/inet.h>

int allowed(const char *addr_text, const char *port_text)
{
    struct in_addr a;
    char *end;
~>    long port = strtol(port_text, &end, 0);
~>    if (inet_aton(addr_text, &a) == 0)
        return 0;
~>    in_addr_t raw = inet_addr(addr_text);
~>    unsigned long long mask = strtoull(getenv("ACL_MASK"), NULL, 0);
    return check(a, port, raw, mask);
}
