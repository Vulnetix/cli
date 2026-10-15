#include <string.h>

int process_heartbeat(SSL *s, unsigned char *p)
{
    unsigned int payload;
    unsigned char *bp, *pl;
    unsigned short hbtype = *p++;
    n2s(p, payload);
    pl = p;
    bp = OPENSSL_malloc(1 + 2 + payload + 16);
    *bp++ = 2;
    s2n(payload, bp);
~>    memcpy(bp, pl, payload);
    return 0;
}
