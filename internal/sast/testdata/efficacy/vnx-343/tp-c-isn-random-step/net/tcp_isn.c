#include <stdlib.h>

static unsigned int last_isn;

unsigned int tcp_new_isn(struct tcb *tcb)
{
    unsigned int isn;
~>    isn = last_isn + (rand() % 64000);
    last_isn = isn;
~>    tcb->snd_isn += rand() & 0xffff;
    return isn;
}
