#include <signal.h>
#include <stdlib.h>
#include <syslog.h>

static void on_term(int sig)
{
    syslog(LOG_INFO, "terminating on %d", sig);
    exit(0);
}

void setup_signals(void)
{
    struct sigaction act;

    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGTERM);
    sigaddset(&act.sa_mask, SIGINT);
    act.sa_flags = 0;
    act.sa_handler = on_term;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
}
