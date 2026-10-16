#include <pthread.h>
#include <string.h>

static void *worker(void *arg)
{
    char *line = arg;
~>    char *tok = strtok(line, ",");
    while (tok != NULL) {
        handle(tok);
~>        tok = strtok(NULL, ",");
    }
    return NULL;
}

int start(char *line)
{
    pthread_t t;
    pthread_create(&t, NULL, worker, line);
    return pthread_join(t, NULL);
}
