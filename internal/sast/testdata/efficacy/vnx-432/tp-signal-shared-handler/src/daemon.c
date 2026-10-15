#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

static char *global_buf;

static void sh(int sig)
{
    syslog(LOG_NOTICE, "caught signal %d", sig);
    free(global_buf);
    sleep(10);
    exit(0);
}

int main(int argc, char *argv[])
{
~>    signal(SIGHUP, sh);
~>    signal( SIGTERM, &sh );
    global_buf = malloc(512);
    for (;;)
        pause();
}
