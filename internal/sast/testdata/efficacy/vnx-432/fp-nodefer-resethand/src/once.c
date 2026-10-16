#include <signal.h>
#include <stdio.h>
#include <string.h>

static void on_int(int sig)
{
    printf("interrupted by %d, press again to quit\n", sig);
}

void install(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_int;
    sa.sa_flags = SA_NODEFER | SA_RESETHAND;
    sigaction(SIGINT, &sa, NULL);
}
