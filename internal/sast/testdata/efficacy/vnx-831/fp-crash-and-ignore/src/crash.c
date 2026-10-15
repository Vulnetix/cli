#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void crash(int sig)
{
    fprintf(stderr, "fatal signal %d\n", sig);
    abort();
}

void setup(void)
{
    signal(SIGSEGV, crash);
    signal(SIGBUS, crash);
    signal(SIGFPE, crash);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    signal(SIGTTOU, SIG_DFL);
}
