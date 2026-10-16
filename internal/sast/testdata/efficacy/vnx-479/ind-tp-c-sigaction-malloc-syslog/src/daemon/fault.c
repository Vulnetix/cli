#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

static void
fault_handler(int sig, siginfo_t *info, void *uctx)
{
    (void) uctx;
~>    char *msg = malloc(128);
~>    syslog(LOG_CRIT, "fault %d at %p", sig, info->si_addr);
~>    free(msg);
    _exit(1);
}

int fault_init(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = fault_handler;
    if (sigaction(SIGSEGV, &sa, NULL) != 0)
        return -1;
    return sigaction(SIGFPE, &sa, NULL);
}
