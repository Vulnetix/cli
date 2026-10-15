#include <pthread.h>
#include <stdio.h>

struct queue {
    pthread_mutex_t lock;
    int head, tail;
};

void queue_create(struct queue *q)
{
~>    if (pthread_mutex_init(&q->lock,
                           NULL) != 0) {
        perror("pthread_mutex_init");
    }
    q->head = q->tail = 0;
}
