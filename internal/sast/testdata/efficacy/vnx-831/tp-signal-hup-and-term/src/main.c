#include <signal.h>
#include <stdlib.h>
#include <syslog.h>

static char *global_buffer;

static void handler(int sig)
{
    syslog(LOG_NOTICE, "caught signal %d", sig);
    free(global_buffer);
    global_buffer = NULL;
}

int main(void)
{
    global_buffer = malloc(4096);
~>    signal(SIGHUP, handler);
~>    signal(SIGTERM, handler);
    for (;;) {
    }
}
