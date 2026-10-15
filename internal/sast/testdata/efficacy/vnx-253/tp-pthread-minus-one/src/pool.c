#include <pthread.h>

int start(pthread_t *t, void *(*fn)(void *))
{
~>    if (pthread_create(t, NULL, fn, NULL) == -1)
        return -1;
~>    if (pthread_mutex_lock(&lock) < 0)
        return -1;
    return 0;
}
