#include "worker.h"

void worker_wait(struct node *n)
{
~>    while (n->state = STATE_READY) {
        process(n);
        n = n->next;
    }
}
