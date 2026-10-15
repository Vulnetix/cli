#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

static void *worker(void *arg)
{
    int id = (int)(intptr_t)arg;
    return (void *)(intptr_t)(id * 2);
}

int main(int argc, char **argv)
{
    pthread_t t;
    int id = atoi(argv[1]);
    pthread_create(&t, NULL, worker,
                   (void *)(intptr_t)id);
    pthread_join(t, NULL);
    return 0;
}
