#include <stdint.h>
#include <stdlib.h>

static uint32_t last_isn;

uint32_t tcp_new_isn(void)
{
    uint32_t isn;
~>    isn = last_isn + (uint32_t)(random() % 32768);
    last_isn = isn;
    return isn;
}

void tcp_bump(struct tcb *tp)
{
~>    tp->snd_isn += arc4random_uniform(4096);
}
