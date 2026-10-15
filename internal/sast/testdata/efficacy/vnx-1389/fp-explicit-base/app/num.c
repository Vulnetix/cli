#include <stdlib.h>
#include <arpa/inet.h>

long parse(const char *s, struct in_addr *out)
{
    char *end;
    long a = strtol(s, &end, 10);
    unsigned long b = strtoul(s, NULL, 16);
    long c = strtol("0x10", NULL, 0);
    inet_pton(AF_INET, s, out);
    in_addr_t lo = inet_addr("127.0.0.1");
    return a + b + c + lo;
}
