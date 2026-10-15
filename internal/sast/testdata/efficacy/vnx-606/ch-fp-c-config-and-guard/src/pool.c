#include <stdlib.h>

#define MAX_WORKERS 64

void start_workers(char **argv)
{
    int workers = atoi(argv[1]);
    if (workers <= 0 || workers > MAX_WORKERS)
        workers = 4;
    for (int i = 0; i < workers; i++) {
        spawn_worker(i);
    }
    int cfg = atoi("8");
    for (int i = 0; i < cfg; i++) {
        spawn_worker(i);
    }
}
