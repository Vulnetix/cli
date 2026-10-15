#include "auth.h"

int check(struct session *s, int uid)
{
~>    if (s->uid = uid)
        return grant(s);
~>    if (s->flags[0] = FLAG_ADMIN) {
        return grant_admin(s);
    }
    return 0;
}
