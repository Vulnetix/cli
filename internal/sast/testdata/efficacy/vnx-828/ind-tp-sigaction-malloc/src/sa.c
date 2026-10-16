#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

static void on_term(int sig)
{
~>    char *msg = malloc(128);
    strcpy(msg, "terminating");
~>    syslog(LOG_INFO, "%s", msg);
~>    free(msg);
}

int install(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_term;
    return sigaction(SIGTERM, &sa, NULL);
}
