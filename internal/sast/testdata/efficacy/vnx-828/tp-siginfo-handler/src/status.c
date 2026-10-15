#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void on_status(int sig, siginfo_t *info, void *ctx)
{
    char line[128];
    time_t now = time(NULL);
~>    struct tm *tm = localtime(&now);
~>    int n = snprintf(line, sizeof line, "status %d from %p\n", sig, info->si_addr);
    write(STDERR_FILENO, line, (size_t)n);
    (void)ctx;
    (void)tm;
    _exit(128 + sig);
}

void install_status_handler(void)
{
    struct sigaction act;
    memset(&act, 0, sizeof act);
    act.sa_sigaction = on_status;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &act, NULL);
}
