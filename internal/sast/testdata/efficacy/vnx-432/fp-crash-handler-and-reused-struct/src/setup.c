#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void on_crash(int sig, siginfo_t *info, void *ctx)
{
    fprintf(stderr, "crashed with %d\n", sig);
    exit(1);
}

static void on_term(int sig)
{
    fprintf(stderr, "terminating\n");
    exit(0);
}

static void on_usr1(int sig)
{
    printf("usr1\n");
}

void install(void)
{
    struct sigaction act;

    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO | SA_RESETHAND;
    act.sa_sigaction = on_crash;
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
    sigaction(SIGFPE, &act, NULL);

    act.sa_flags = 0;
    act.sa_handler = on_term;
    sigaction(SIGTERM, &act, NULL);
    act.sa_handler = on_usr1;
    sigaction(SIGUSR1, &act, NULL);
}
