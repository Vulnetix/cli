#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void on_stop(int sig)
{
~>    fprintf(stderr, "stopping on signal %d\n", sig);
~>    exit(1);
}

void install(void)
{
    signal(SIGSEGV, on_stop);
    signal(SIGTERM, on_stop);
}
