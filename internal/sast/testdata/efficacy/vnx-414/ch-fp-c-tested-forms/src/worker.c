#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/file.h>

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static sem_t s;

int worker_step(int fd)
{
	int rc;
	if ((rc = pthread_mutex_trylock(&m)) != 0)
		return rc;
	pthread_mutex_unlock(&m);

	while (sem_trywait(&s) == -1 && errno == EINTR)
		continue;

	rc = flock(fd, LOCK_EX | LOCK_NB);
	if (rc != 0)
		return -1;
	flock(fd, LOCK_UN);

	int got =
	    pthread_mutex_trylock(&m);
	if (got == 0)
		pthread_mutex_unlock(&m);
	return pthread_mutex_trylock(&m) == 0 ? 0 : -1;
}
