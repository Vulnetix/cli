#include <pthread.h>
#include <string.h>

static void *worker(void *arg) {
    char *buf = arg;
~>    char *tok = strtok (buf, ",");
    while (tok) {
~>        tok = strtok (NULL, ",");
    }
    return NULL;
}

int start(char *a, char *b) {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, worker, a);
    pthread_create(&t2, NULL, worker, b);
    return 0;
}
