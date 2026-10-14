#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct session;
void session_close(struct session *s);

void finish(struct session *sess, char *name)
{
    free(name);
~>    fprintf(stderr, "closing %s\n", name);
    free(sess);
    if (sess != NULL)
~>        session_close( sess );
}

char *rename_buf(char *old, const char *src, size_t n)
{
    free(old);
~>    memcpy(old,
           src, n);
    return NULL;
}

char *stale(char *old)
{
    free(old);
~>    return old;
}
