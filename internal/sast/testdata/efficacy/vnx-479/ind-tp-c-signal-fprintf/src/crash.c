#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void on_crash(int sig)
{
~>    fprintf(stderr, "fatal signal %d, writing report\n", sig);
~>    fflush(stderr);
    _exit(128 + sig);
}

void install_crash_handlers(void)
{
    signal(SIGSEGV, on_crash);
    signal(SIGBUS, on_crash);
}
