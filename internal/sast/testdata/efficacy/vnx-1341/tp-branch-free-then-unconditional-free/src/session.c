#include <stdlib.h>

struct session { char *token; };

void session_end(struct session *s, int expired)
{
    if (expired) {
        free(s->token);
    }
~>    free(s->token);
    free(s);
}
