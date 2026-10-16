#include <stdlib.h>

void build_packet(const char *field)
{
    char pkt[64];
    char *end;
    long v = strtol(field, &end, 16);

~>    pkt[3] = v;
    send_packet(pkt);
}
