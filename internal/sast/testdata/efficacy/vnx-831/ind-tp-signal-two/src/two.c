#include <signal.h>
#include <stdlib.h>
#include <syslog.h>

static char *global_buffer;

static void handler(int sig)
{
    syslog(LOG_NOTICE, "caught signal %d", sig);
    free(global_buffer);
}

void setup(void)
{
~>    signal(SIGHUP, handler);
~>    signal(SIGTERM, handler);
}
