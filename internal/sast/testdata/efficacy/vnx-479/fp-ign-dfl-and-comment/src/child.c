#include <signal.h>
#include <stdio.h>

/* Never call printf() from a handler such as signal(SIGINT, handler). */
// signal(SIGTERM, on_term); printf("x");
int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    printf("started\n");
    return 0;
}
