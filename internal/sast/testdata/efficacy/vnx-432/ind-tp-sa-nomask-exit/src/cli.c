#include <signal.h>
#include <stdlib.h>
#include <syslog.h>

static void on_interrupt(int sig)
{
    syslog(LOG_WARNING, "interrupted by %d, cleaning up", sig);
    remove_lockfile();
    exit(130);
}

void install_interrupt(void)
{
    struct sigaction sa;
    sa.sa_handler = on_interrupt;
    sigemptyset(&sa.sa_mask);
~>    sa.sa_flags = SA_NOMASK;
    sigaction(SIGINT, &sa, NULL);
}
