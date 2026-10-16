#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void crash(int sig)
{
    fprintf(stderr, "crash %d\n", sig);
    abort();
}

int main(void)
{
    signal(SIGSEGV, crash);
    signal(SIGBUS, crash);
    signal(SIGFPE, crash);
    // signal(SIGINT, crash); signal(SIGTERM, crash);
    return 0;
}
