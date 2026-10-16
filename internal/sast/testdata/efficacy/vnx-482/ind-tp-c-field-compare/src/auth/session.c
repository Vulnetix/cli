#include "session.h"

void session_logout(struct session *s)
{
    s->user_id = 0;
~>    s->authenticated == 0;
    s->expires = 0;
}
