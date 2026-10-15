#include <stdlib.h>

struct session {
    char *token;
    char *user;
};

void session_reset(struct session *s)
{
    free(s->token);
    free(s->user);
~>    free(s->token);
}
