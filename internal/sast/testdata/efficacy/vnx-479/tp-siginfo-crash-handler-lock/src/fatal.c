#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static pthread_mutex_t report_lock = PTHREAD_MUTEX_INITIALIZER;

void on_fatal(int sig, siginfo_t *info, void *uctx)
{
    (void)uctx;
~>    pthread_mutex_lock(&report_lock);
~>    fprintf(stderr, "fatal signal %d at %p\n", sig, info->si_addr);
    _exit(1);
}

void setup_fatal_handlers(void)
{
    struct sigaction act;

    memset(&act, 0, sizeof act);
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = on_fatal;
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGILL, &act, NULL);
    sigaction(SIGABRT, &act, NULL);
}
