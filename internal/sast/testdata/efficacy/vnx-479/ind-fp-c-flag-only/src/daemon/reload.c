#include <signal.h>
#include <stdio.h>

static volatile sig_atomic_t got_fault = 0;

static void mark_fault(int sig)
{
    (void) sig;
    got_fault = 1; /* printf would not be safe here */
    abort();
}

void report_if_faulted(void)
{
    if (got_fault)
        printf("a fault was recorded\n");
}

void install(void)
{
    signal(SIGSEGV, mark_fault);
    signal(SIGPIPE, SIG_IGN);
}
