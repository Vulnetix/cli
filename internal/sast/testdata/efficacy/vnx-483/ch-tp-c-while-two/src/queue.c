#include "queue.h"

void drain(struct queue *q)
{
    while (q->head != NULL)
        process(q->head);
~>        q->head = q->head->next;
}
