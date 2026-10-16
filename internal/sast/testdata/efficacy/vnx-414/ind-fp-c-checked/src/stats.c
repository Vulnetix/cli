#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/file.h>

int bump(pthread_mutex_t *m, struct stats *s)
{
    if (pthread_mutex_trylock(m) == EBUSY)
        return -1;
    s->hits++;
    pthread_mutex_unlock(m);

    int rc = sem_trywait(&s->tokens);
    if (rc != 0)
        return -1;

    (void)pthread_mutex_trylock(&s->aux);
    return 0;
}

void file_locks(int fd, struct flock *fl)
{
    flock(fd, LOCK_EX);
    flock(fd, LOCK_UN);
    fcntl(fd, F_SETLKW, fl);
    pthread_mutex_lock(&global_lock);
    /* pthread_mutex_trylock(&global_lock); old approach */
    pthread_mutex_unlock(&global_lock);
}
