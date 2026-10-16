#include <stdlib.h>
#include "session.h"

void session_reset(struct session *s, int keep_user)
{
    free(s->scratch);
    if (keep_user) {
        s->flags |= SESSION_KEEP;
    }
    s->len = 0;
~>    free(s->scratch);
    s->state = SESSION_IDLE;
}
