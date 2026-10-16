#include <stdlib.h>

struct session {
    int fd;
    char *token;
};

int session_finish(struct session *s, int err)
{
    if (err) {
        free(s);
    }
~>    return s->fd;
}
