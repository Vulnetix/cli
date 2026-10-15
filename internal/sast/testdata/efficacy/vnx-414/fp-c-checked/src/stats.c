#include <pthread.h>
#include <sys/file.h>

void stats_bump(struct stats *s)
{
    if (pthread_mutex_trylock(&stats_lock) != 0)
        return;
    s->hits++;
    pthread_mutex_unlock(&stats_lock);
    int rc = pthread_rwlock_trywrlock(&table_lock);
    if (rc == EBUSY)
        return;
    while (sem_trywait(&slots) == -1 && errno == EINTR)
        ;
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        die("already running");
    }
    rc =
        pthread_mutex_trylock(&other_lock);
    return pthread_spin_trylock(&spin);
}
