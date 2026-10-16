#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

static char *state_buf;

static void on_stop(int sig)
{
    fprintf(stderr, "stopping (%d)\n", sig);
    free(state_buf);
    exit(0);
}

void install(void)
{
    struct sigaction sa = { .sa_handler = on_stop, .sa_flags = SA_RESTART };
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
}
