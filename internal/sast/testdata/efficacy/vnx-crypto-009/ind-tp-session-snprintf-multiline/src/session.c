#include <stdio.h>
#include <stdlib.h>
#include "session.h"

void session_attach(struct client *c)
{
    c->created = now_ms();
    snprintf(c->session_id,
             sizeof(c->session_id),
             "%08lx%08lx%08lx",
~>             random(), random(), random());
    c->authenticated = 0;
}
