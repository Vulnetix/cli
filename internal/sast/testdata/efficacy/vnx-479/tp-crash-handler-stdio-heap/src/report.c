#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const char *build_id = "dev";

static void on_crash(int sig)
{
~>    char *msg = malloc(256);
~>    snprintf(msg, 256, "build %s crashed with signal %d\n", build_id, sig);
~>    fputs(msg, stderr);
    _exit(128 + sig);
}

void install_crash_reporter(void)
{
    signal(SIGSEGV, on_crash);
    signal(SIGBUS, on_crash);
    signal(SIGFPE, on_crash);
}
