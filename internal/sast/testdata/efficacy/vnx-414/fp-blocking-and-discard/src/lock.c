#include <pthread.h>

void inc(void)
{
    pthread_mutex_lock(&m);
    count++;
    pthread_mutex_unlock(&m);
    (void)pthread_mutex_trylock(&warm);
    flock(fd, LOCK_EX);
    fcntl(fd, F_SETLKW, &fl);
    my_trylock_wrapper_count++;
}
