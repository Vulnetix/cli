#include "debug.h"

/*
   Never write printf(buf) with a buffer that came from the network.
*/

void notes(struct writer *w, const char *msg)
{
    // printf(msg);
    puts("do not call printf(msg) directly");
    w->printf(msg);
    w.printf(msg);
    my_printf(msg);
    log_printf(msg);
}
