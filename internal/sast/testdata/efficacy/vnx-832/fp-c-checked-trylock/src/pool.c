#include <pthread.h>

static pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;
static int pool_size;

int pool_try_grow(int n)
{
    if (pthread_mutex_trylock(&pool_lock) != 0) {
        return -1;
    }
    pool_size += n;
    pthread_mutex_unlock(&pool_lock);
    return 0;
}

void pool_grow(int n)
{
    pthread_mutex_lock(&pool_lock);
    pool_size += n;
    pthread_mutex_unlock(&pool_lock);
}

int pool_try(int n)
{
    int rc = pthread_mutex_trylock(&pool_lock);
    if (rc == 0) {
        pool_size += n;
        pthread_mutex_unlock(&pool_lock);
    }
    return rc;
}
