#include <signal.h>
#include <stdlib.h>

static volatile sig_atomic_t stop;

static void on_interrupt(int sig)
{
    (void)sig;
    stop = 1;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
~>    signal(SIGINT, on_interrupt);
    signal(SIGTERM, on_interrupt);
    while (!stop) {
    }
    return 0;
}
