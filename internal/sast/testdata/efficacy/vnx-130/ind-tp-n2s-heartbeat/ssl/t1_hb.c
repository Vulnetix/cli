#include <string.h>

int process_heartbeat(SSL *s, unsigned char *p)
{
    unsigned short hbtype;
    unsigned int payload;
    unsigned char *pl, *bp, *buffer;

    hbtype = *p++;
    n2s(p, payload);
    pl = p;
    buffer = OPENSSL_malloc(1 + 2 + payload + 16);
    bp = buffer;
    *bp++ = TLS1_HB_RESPONSE;
    s2n(payload, bp);
~>    memcpy(bp, pl, payload);
    return 0;
}
