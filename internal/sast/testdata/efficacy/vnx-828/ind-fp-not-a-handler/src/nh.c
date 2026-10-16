#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

void report(int code)
{
    printf("code %d\n", code);
    exit(code);
}

static void crash(int sig)
{
    fprintf(stderr, "fatal %d\n", sig);
    abort();
}

int main(void)
{
    signal(SIGSEGV, crash);
    report(0);
    /* signal(SIGINT, report); */
    return 0;
}
