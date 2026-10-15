#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

void handle_hup(int signo, siginfo_t *info, void *ctx)
{
    time_t now = time(NULL);
~>    fprintf(stderr, "reload at %s", ctime(&now));
~>    char *copy = strdup("reloading");
    (void)copy;
}

int install(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handle_hup;
    sa.sa_flags = SA_SIGINFO;
    return sigaction(SIGHUP, &sa, NULL);
}
