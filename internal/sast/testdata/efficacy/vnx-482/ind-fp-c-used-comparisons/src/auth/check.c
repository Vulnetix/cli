#include "session.h"

int is_logged_in(const struct session *s)
{
    int ok = s->authenticated == 1;
    if (s->user_id == 0)
        return 0;
    log_flag("auth", s->expires == 0);
    return ok && s->expires == 0 ? 1 : 0;
}
