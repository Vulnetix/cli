#include <stdlib.h>
#include <string.h>

struct session {
    unsigned char key[32];
    int id;
};

void session_destroy(unsigned char *session_key, size_t len)
{
~>    memset(session_key,
           0,
           len);
    free(session_key);
}

void session_free(struct session *s)
{
~>    memset(s->key, 0, sizeof(s->key));
    free(s);
}
