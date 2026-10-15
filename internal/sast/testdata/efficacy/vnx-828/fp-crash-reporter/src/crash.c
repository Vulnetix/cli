#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void crash_report(int sig, siginfo_t *info, void *uctx)
{
    void *frames[64];
    int n = backtrace(frames, 64);
    fprintf(stderr, "crashed with signal %d at %p\n", sig, info->si_addr);
    backtrace_symbols_fd(frames, n, 2);
    (void)uctx;
    exit(128 + sig);
}

static void on_abort(int sig)
{
    fprintf(stderr, "aborted (%d)\n", sig);
}

void install_crash_reporter(void)
{
    struct sigaction act;
    memset(&act, 0, sizeof act);
    act.sa_sigaction = crash_report;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
    sigaction(SIGFPE, &act, NULL);
    signal(SIGABRT, on_abort);
}
