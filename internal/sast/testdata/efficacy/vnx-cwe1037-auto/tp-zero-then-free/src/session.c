#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "session.h"

void session_destroy(struct session *s)
{
    if (s == NULL)
        return;
~>    memset(s->session_key, 0, sizeof(s->session_key));
    free(s);
}

void key_release(unsigned char *key, size_t len)
{
~>    bzero(key, len);
    free(key);
}

void wipe_passphrase(char *passphrase, size_t n)
{
~>    memset(passphrase, '\0',
           n);
    /* gone */
    free(passphrase);
}
