#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

void on_report(int code)
{
    printf("report %d\n", code);
    free(NULL);
}

void reset_signals(void)
{
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_IGN);
}

int main(void)
{
    on_report(1);
    reset_signals();
    return 0;
}
