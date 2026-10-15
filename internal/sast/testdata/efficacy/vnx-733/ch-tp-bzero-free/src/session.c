#include <stdlib.h>
#include <strings.h>

void session_close(struct session *s) {
    unsigned char *secret = s->master_secret;
~>    bzero(secret, s->secret_len);
    free(secret);
    s->master_secret = NULL;
}
