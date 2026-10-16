#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

void sigint_handler(int sig)
{
~>    printf("Caught signal %d\n", sig);
~>    exit(1);
}

int main(void)
{
    signal(SIGINT, sigint_handler);
    for (;;) pause();
}
