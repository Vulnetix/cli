#include <pthread.h>

static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;

void enqueue(struct queue *q, void *item)
{
    pthread_mutex_lock(&qlock);
    q->items[q->tail++] = item;
    if (q->tail == q->cap)
        grow(q);
~>    pthread_mutex_lock(&qlock);
    pthread_mutex_unlock(&qlock);
}

void drain(struct queue *q)
{
    pthread_mutex_lock(&q->mu);
    q->count = 0;
    pthread_mutex_unlock(&q->mu);
~>    pthread_mutex_unlock(&q->mu);
}
