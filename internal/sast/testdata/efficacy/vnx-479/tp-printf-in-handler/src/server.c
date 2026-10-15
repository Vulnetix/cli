#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

static char *buffer;

static void on_term(int sig)
{
~>    printf("caught signal %d\n", sig);
~>    syslog(LOG_INFO, "shutting down");
~>    free(buffer);
~>    exit(1);
}

int main(void)
{
    buffer = malloc(4096);
    signal(SIGTERM, on_term);
    signal(SIGINT, &on_term);
    for (;;) {
        puts("working");
    }
}
