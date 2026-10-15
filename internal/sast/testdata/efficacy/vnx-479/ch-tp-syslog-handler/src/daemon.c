#include <signal.h>
#include <syslog.h>
#include <stdlib.h>

static void on_term(int sig)
{
~>    syslog(LOG_INFO, "caught signal %d", sig);
~>    exit(0);
}

int main(void)
{
    signal(SIGTERM, on_term);
    for (;;) {
        pause();
    }
}
