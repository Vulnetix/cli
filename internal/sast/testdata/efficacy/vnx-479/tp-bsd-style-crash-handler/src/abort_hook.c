#include <signal.h>
#include <stdlib.h>
#include <syslog.h>

static void
on_abort(int sig)
{
~>    syslog(LOG_CRIT, "aborting on signal %d", sig);
~>    exit(70);
}

void
hook_abort(void)
{
    signal(SIGABRT, on_abort);
}
