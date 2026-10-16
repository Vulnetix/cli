#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void on_fault(int sig, siginfo_t *info, void *uc)
{
    (void)uc;
    fprintf(stderr, "fatal signal %d at %p\n", sig, info->si_addr);
    abort();
}

void install_crash_reporter(void)
{
    struct sigaction act;

    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NODEFER | SA_SIGINFO;
    act.sa_sigaction = on_fault;
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
}
