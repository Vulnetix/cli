#include <pthread.h>

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void a(void)
{
    if (pthread_mutex_trylock(&m) == 0) {
        pthread_mutex_unlock(&m);
    }
    pthread_mutex_lock(&m);
    pthread_mutex_unlock(&m);
    int rc = pthread_mutex_trylock(&m);
    if (rc == 0) pthread_mutex_unlock(&m);
}
