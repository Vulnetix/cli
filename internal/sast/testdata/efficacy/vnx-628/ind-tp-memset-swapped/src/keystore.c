#include <string.h>

struct session { unsigned char key[32]; int used; };

void session_close(struct session *s)
{
~>    memset(s->key, sizeof(s->key), 0);
    s->used = 0;
}
