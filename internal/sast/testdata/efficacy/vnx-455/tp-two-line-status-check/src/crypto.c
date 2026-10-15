#include <stdio.h>
#include "crypto.h"

int start_session(struct session *s)
{
    int rc;

    rc = crypto_init(&s->ctx);
~>    if (rc != 0)
        printf("crypto_init returned %d\n", rc);
    s->ready = 1;
    return encrypt_handshake(s);
}
