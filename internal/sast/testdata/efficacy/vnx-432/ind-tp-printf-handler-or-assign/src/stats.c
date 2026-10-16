#include <signal.h>
#include <stdio.h>
#include <string.h>

static unsigned long requests_served;

static void dump_stats(int signo)
{
    printf("signal %d: %lu requests served\n", signo, requests_served);
    fflush(stdout);
}

int install_stats_handler(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = dump_stats;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
~>    sa.sa_flags |= SA_NODEFER;
    return sigaction(SIGUSR1, &sa, NULL);
}
