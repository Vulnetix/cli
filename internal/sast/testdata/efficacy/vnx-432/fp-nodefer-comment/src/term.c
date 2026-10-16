#include <signal.h>
#include <stdlib.h>
#include <string.h>

static char *scratch;

static void on_term(int sig)
{
    (void)sig;
    free(scratch);
    exit(0);
}

void install(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term;
    /* sa.sa_flags = SA_NODEFER; removed: the handler must not re-enter */
    sa.sa_flags = SA_RESTART;
    sigaction(SIGTERM, &sa, NULL);
    puts("SA_NODEFER is not used here");
}
