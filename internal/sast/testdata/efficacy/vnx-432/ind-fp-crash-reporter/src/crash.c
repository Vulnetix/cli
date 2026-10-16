#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>

static void crash_handler(int sig, siginfo_t *info, void *ctx)
{
    void *frames[64];
    int n = backtrace(frames, 64);
    fprintf(stderr, "fatal signal %d at %p\n", sig, info->si_addr);
    backtrace_symbols_fd(frames, n, 2);
    abort();
}

void install_crash_handler(void)
{
    struct sigaction sa;
    sa.sa_sigaction = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}
