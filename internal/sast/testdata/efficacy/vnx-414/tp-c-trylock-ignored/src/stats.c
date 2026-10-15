#include <pthread.h>
#include <semaphore.h>

static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t table_lock;
static sem_t slots;

void stats_bump(struct stats *s)
{
~>  pthread_mutex_trylock(&stats_lock);
    s->hits++;
    pthread_mutex_unlock(&stats_lock);
}

void table_put(struct table *t, int k, int v)
{
    if (t == NULL)
        return;
~>  pthread_rwlock_trywrlock( &table_lock );
    t->vals[k] = v;
    pthread_rwlock_unlock(&table_lock);
~>  sem_trywait(&slots);
    t->used++;
}
