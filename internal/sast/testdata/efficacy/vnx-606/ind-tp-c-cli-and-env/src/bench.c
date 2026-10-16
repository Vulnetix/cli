#include <stdio.h>
#include <stdlib.h>

static void spawn_worker(long id);
static void run_once(void);

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s ITERATIONS\n", argv[0]);
        return 1;
    }

    int iterations = atoi(argv[1]);
~>    while (iterations-- > 0) {
        run_once();
    }

    long workers = strtol(getenv("BENCH_WORKERS"), NULL, 10);
~>    for (long w = 0; w < workers; w++) {
        spawn_worker(w);
    }

    unsigned int rounds;
    printf("rounds? ");
    scanf("%u", &rounds);
~>    for (unsigned int r = 0; r < rounds; r++) {
        run_once();
    }
    return 0;
}

static void spawn_worker(long id) { printf("worker %ld\n", id); }
static void run_once(void) { puts("tick"); }
