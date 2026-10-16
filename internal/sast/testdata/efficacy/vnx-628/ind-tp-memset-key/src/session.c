#include <string.h>
#include <stdlib.h>
#include "session.h"

void session_destroy(struct session *s)
{
    if (s == NULL)
        return;
~>    memset(s->key, sizeof(s->key), 0);
~>    memset(s->iv, 16, 0);
    free(s->peer);
    free(s);
}
