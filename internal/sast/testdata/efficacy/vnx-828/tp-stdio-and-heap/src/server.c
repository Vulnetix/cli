#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

static char *last_error;

static void on_hup(int sig)
{
~>    printf("reloading on signal %d\n", sig);
~>    syslog(LOG_INFO, "SIGHUP received");
~>    free(last_error);
~>    last_error = malloc(64);
}

int main(void)
{
    signal(SIGHUP, on_hup);
    for (;;) {
        pause();
    }
}
