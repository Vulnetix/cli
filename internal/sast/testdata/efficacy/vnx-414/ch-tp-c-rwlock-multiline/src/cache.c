#include <pthread.h>

struct cache { pthread_rwlock_t rw; int gen; };
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;

void cache_refresh(struct cache *c)
{
~>	pthread_rwlock_trywrlock(&c->rw);
	c->gen++;
	pthread_rwlock_unlock(&c->rw);
}

void bump(int *counter)
{
~>	pthread_mutex_trylock(
	    &state_lock);
	(*counter)++;
	pthread_mutex_unlock(&state_lock);
}
