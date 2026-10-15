#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void on_int(int sig)
{
    printf("interrupt %d\n", sig);
    exit(1);
}

static void on_term(int sig)
{
    printf("terminate %d\n", sig);
    exit(0);
}

int main(void)
{
    signal(SIGINT, on_int);
    signal(SIGTERM, on_term);
    signal(SIGINT, on_int);
    return 0;
}
