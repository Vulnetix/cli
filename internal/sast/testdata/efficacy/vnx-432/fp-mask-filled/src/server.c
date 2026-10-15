#include <signal.h>
#include <stdio.h>
#include <string.h>

static FILE *journal;

static void on_shutdown(int sig)
{
    fprintf(journal, "shutting down on %d\n", sig);
}

void install_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sigfillset(&sa.sa_mask);
    sa.sa_handler = on_shutdown;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}
