#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void on_hup(int signo)
{
~>    fprintf(stderr, "reloading config\n");
~>    free(config);
}

int install(void)
{
    struct sigaction sa = { .sa_handler = on_hup, .sa_flags = SA_RESTART };
    sigemptyset(&sa.sa_mask);
    return sigaction(SIGHUP, &sa, NULL);
}
