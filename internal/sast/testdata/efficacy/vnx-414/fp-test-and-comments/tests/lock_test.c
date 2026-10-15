#include <pthread.h>

void test_contention(void)
{
    pthread_mutex_trylock(&m);
    assert_busy();
}
