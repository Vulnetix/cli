#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void *handle(void *arg) {
    char *line = arg;
~>    char *tok = strtok(line, ",");
    while (tok != NULL) {
        process(tok);
~>        tok = strtok(NULL, ",");
    }
    time_t now = time(NULL);
~>    struct tm *t = localtime(&now);
~>    printf("done at %s", asctime(t));
    return NULL;
}

int start(char **lines, int n) {
    pthread_t ids[16];
    for (int i = 0; i < n; i++)
        pthread_create(&ids[i], NULL, handle, lines[i]);
    return 0;
}
