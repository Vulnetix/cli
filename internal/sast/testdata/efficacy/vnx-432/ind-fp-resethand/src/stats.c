#include <signal.h>
#include <stdio.h>

static void dump_once(int signo)
{
    printf("dumping on %d\n", signo);
}

int install_dump(void)
{
    struct sigaction sa;
    sa.sa_handler = dump_once;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER | SA_RESETHAND;
    return sigaction(SIGUSR2, &sa, NULL);
}
