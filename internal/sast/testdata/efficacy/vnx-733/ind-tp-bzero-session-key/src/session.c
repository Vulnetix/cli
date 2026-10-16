#include <stdlib.h>
#include <strings.h>

struct conn;
void conn_set_cipher(struct conn *c, const unsigned char *k, size_t n);

void rekey(struct conn *c, size_t n)
{
    unsigned char *session_key = calloc(1, n);
    if (!session_key)
        return;
    arc4random_buf(session_key, n);
    conn_set_cipher(c, session_key, n);
~>    bzero(session_key, n);
    free(session_key);
}
