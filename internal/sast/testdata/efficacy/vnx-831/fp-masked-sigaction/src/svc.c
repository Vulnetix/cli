#include <signal.h>
#include <stdio.h>
#include <string.h>

static void on_reload(int signo)
{
    fprintf(stderr, "reload %d\n", signo);
}

void install(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_reload;
    sigfillset(&sa.sa_mask);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}
