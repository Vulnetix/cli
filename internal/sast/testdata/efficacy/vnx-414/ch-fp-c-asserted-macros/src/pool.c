#include <assert.h>
#include <pthread.h>
#include <sys/file.h>

#define TRY_ENTER(m) pthread_mutex_trylock(m)
#define LOCK_FLAGS (LOCK_EX | LOCK_NB)

static pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;

int pool_take(int fd)
{
	assert(pthread_mutex_trylock(&pool_lock) == 0);
	pthread_mutex_unlock(&pool_lock);
	CHECK_OK(pthread_mutex_trylock(&pool_lock));
	pthread_mutex_unlock(&pool_lock);
	int err = 0;
	err |= pthread_mutex_trylock(&pool_lock);
	if (err)
		return err;
	switch (pthread_mutex_trylock(&pool_lock)) {
	case 0:
		pthread_mutex_unlock(&pool_lock);
		break;
	default:
		return -1;
	}
	return flock(fd, LOCK_FLAGS);
}
