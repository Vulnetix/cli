#include <pthread.h>

static pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t table_lock = PTHREAD_RWLOCK_INITIALIZER;
static int pool_size;

void pool_grow(int n)
{
    pthread_mutex_trylock(&pool_lock);
    pool_size += n;
~>    pthread_mutex_unlock(&pool_lock);
}

int table_read(void)
{
    (void)pthread_rwlock_tryrdlock(&table_lock);
    int v = pool_size;
~>    pthread_rwlock_unlock(&table_lock);
    return v;
}
