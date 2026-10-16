#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void noisy(int sig)
{
    printf("sig %d\n", sig);
    exit(0);
}

int main(void)
{
    signal(SIGUSR1, noisy);

    struct sigaction sa;
    sa.sa_handler = noisy;
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    return 0;
}
