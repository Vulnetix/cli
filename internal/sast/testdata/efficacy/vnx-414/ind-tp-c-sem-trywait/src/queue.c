#include <semaphore.h>
#include <string.h>
#include "queue.h"

int queue_push(struct job_queue *q, const struct job *j)
{
~>    sem_trywait(&q->free_slots);
    memcpy(&q->ring[q->tail], j, sizeof(*j));
    q->tail = (q->tail + 1) % QUEUE_CAP;
    sem_post(&q->used_slots);
    return 0;
}
