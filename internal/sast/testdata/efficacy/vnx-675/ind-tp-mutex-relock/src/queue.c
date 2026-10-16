#include <pthread.h>

void push(queue_t *q, item_t item) {
    pthread_mutex_lock(&q->qlock);
    q->items[q->tail++] = item;
~>    pthread_mutex_lock(&q->qlock);
    q->count++;
    pthread_mutex_unlock(&q->qlock);
}
