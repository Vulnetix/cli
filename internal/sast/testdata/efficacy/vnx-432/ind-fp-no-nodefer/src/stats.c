#include <signal.h>
#include <stdio.h>

/* sa.sa_flags = SA_NODEFER; was removed: the handler calls printf */
static void dump_stats(int signo)
{
    printf("signal %d\n", signo);
}

int install_stats_handler(void)
{
    struct sigaction sa;
    sa.sa_handler = dump_stats;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    return sigaction(SIGUSR1, &sa, NULL);
}
