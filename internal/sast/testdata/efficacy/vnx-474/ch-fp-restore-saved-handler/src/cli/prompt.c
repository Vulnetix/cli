#include <signal.h>
#include <stdio.h>

typedef void (*sighandler_t)(int);

int ask(char *buf, int n)
{
    sighandler_t prev = signal(SIGINT, SIG_IGN);
    int ok = fgets(buf, n, stdin) != NULL;
    signal(SIGINT, prev);
    return ok;
}
