#include <string.h>
#include "session.h"

struct session {
    char user[32];
    char host[64];
    int uid;
};

void session_init(struct session *s, const char *user, const char *host)
{
~>    strncpy(s->user, user, sizeof(s->user));
~>    strncpy(s->host, host, sizeof s->host);
    s->uid = lookup_uid(s->user);
    log_info("session for %s@%s", s->user, s->host);
}
