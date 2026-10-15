#include <signal.h>
#include <stdio.h>

void report(const char *msg)
{
    printf("%s\n", msg);
}

int start(void)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    report("started");
    return 0;
}
