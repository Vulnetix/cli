#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

static char *config_buf;

static void on_hup(int sig)
{
    syslog(LOG_NOTICE, "reloading on signal %d", sig);
    free(config_buf);
    config_buf = NULL;
}

void install_reload(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_hup;
    sigemptyset(&sa.sa_mask);
~>    sa.sa_flags = SA_NODEFER | SA_RESTART;
    sigaction(SIGHUP, &sa, NULL);
}
