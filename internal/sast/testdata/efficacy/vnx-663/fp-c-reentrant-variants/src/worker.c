#include <pthread.h>
#include <string.h>
#include <time.h>

/* strtok() and localtime() are not used here: they are not thread-safe. */
static void *handle(void *arg) {
    char *save = NULL;
    char *tok = strtok_r(arg, ",", &save);
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    const char *msg = "strtok(";
    my_localtime(&now);
    obj->gmtime(&now);
    return tok;
}

int start(char *line) {
    pthread_t id;
    return pthread_create(&id, NULL, handle, line);
}
