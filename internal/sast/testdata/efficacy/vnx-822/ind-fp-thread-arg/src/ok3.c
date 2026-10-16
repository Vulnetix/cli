#include <pthread.h>
#include <stdint.h>
struct ctx { int id; };
static void *worker(void *arg)
{
    struct ctx *c = (struct ctx *)arg;
    int id = (int)(intptr_t)arg;
    return (void *)(intptr_t)(c ? c->id : id);
}
int start(int id)
{
    pthread_t t;
    return pthread_create(&t, NULL, worker, (void *)(intptr_t)id);
}
