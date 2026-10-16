#include <pthread.h>
#include "queue.h"

static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;

void queue_push(struct queue *q, void *item)
{
    pthread_mutex_lock(&qlock);
    q->items[q->tail++] = item;
    q->count++;
~>    pthread_mutex_lock(&qlock);
    q->tail %= QUEUE_CAP;
    pthread_mutex_unlock(&qlock);
}

void queue_reset(struct queue *q)
{
    pthread_mutex_lock(&q->mu);
    q->count = 0;
    pthread_mutex_unlock(&q->mu);
    q->tail = 0;
~>    pthread_mutex_unlock(&q->mu);
}
