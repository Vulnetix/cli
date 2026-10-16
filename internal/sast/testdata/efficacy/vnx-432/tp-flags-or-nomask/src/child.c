#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void on_child(int sig, siginfo_t *info, void *ctx)
{
    (void)ctx;
    fprintf(stderr, "child %d exited (signal %d)\n", (int)info->si_pid, sig);
}

int setup(void)
{
    struct sigaction act;

    memset(&act, 0, sizeof act);
    act.sa_sigaction = on_child;
    act.sa_flags = SA_SIGINFO;
~>    act.sa_flags |= SA_NOMASK;
    return sigaction(SIGCHLD, &act, NULL);
}
