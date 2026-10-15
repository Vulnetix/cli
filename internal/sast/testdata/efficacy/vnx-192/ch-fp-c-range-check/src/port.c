#include <errno.h>
#include <stdlib.h>

int parse_port(const char *s, unsigned short *out)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || v < 1 || v > 65535)
        return -1;
    *out = (unsigned short)v;
    return 0;
}
