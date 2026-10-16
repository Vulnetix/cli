#include <pthread.h>

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static int counter;

void bump(void)
{
    pthread_mutex_trylock(&m);
    counter++;
~>    pthread_mutex_unlock(&m);
}
