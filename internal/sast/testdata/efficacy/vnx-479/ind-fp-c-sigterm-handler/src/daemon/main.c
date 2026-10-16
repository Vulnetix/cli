#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void on_term(int sig)
{
    fprintf(stderr, "terminating on %d\n", sig);
    exit(0);
}

int main(void)
{
    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    return run_loop();
}
