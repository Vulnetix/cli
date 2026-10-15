#include <pthread.h>

void queue_push(struct queue *q, void *item)
{
    pthread_mutex_lock(&q->lock);
    q->items[q->n++] = item;
~>    pthread_mutex_lock(&q->lock);
    pthread_mutex_unlock(&q->lock);
}
