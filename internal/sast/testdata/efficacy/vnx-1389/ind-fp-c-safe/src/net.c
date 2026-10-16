#include <arpa/inet.h>
#include <stdlib.h>

int parse(const char *addr_text, const char *port_text) {
    struct in_addr a;
    char *end;
    long port = strtol(port_text, &end, 10);
    if (inet_pton(AF_INET, addr_text, &a) != 1) return 0;
    /* strtol(s, &end, 0) and inet_aton would guess the radix */
    const char *doc = "inet_aton(addr, &a); strtol(p, &e, 0)";
    return (int)port;
}
