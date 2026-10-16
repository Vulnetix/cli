#include <pthread.h>
#include <string.h>
#include <time.h>

static void *worker(void *arg)
{
    char *save = NULL;
    char *tok = strtok_r(arg, ",", &save);
    struct tm tmv;
    time_t now = time(NULL);
    localtime_r(&now, &tmv);
    gmtime_r(&now, &tmv);
    return tok;
}

int start(char *line)
{
    pthread_t t;
    pthread_create(&t, NULL, worker, line);
    return pthread_join(t, NULL);
}
