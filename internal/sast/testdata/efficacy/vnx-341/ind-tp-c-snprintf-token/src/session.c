#include <stdio.h>
#include <time.h>
#include <unistd.h>

struct session {
    char session_token[64];
    int uid;
};

void session_init(struct session *s, int uid)
{
    s->uid = uid;
~>    snprintf(s->session_token, sizeof(s->session_token), "%ld-%d", (long) time(NULL), (int) getpid());
}
