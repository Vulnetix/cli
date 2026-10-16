#include <pthread.h>

void bump(struct stats *s) {
    pthread_mutex_lock(&s->mu);
    s->hits++;
    pthread_mutex_unlock(&s->mu);
    log_debug("bumped");
~>    pthread_mutex_unlock(&s->mu);
}
