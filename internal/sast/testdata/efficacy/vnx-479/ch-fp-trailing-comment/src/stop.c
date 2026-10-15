#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;

static void on_term(int sig)
{
    stop_requested = 1; /* main loop will free buffers and exit() */
    (void)sig;          // never delete or printf here
}

void setup(void)
{
    signal(SIGTERM, on_term);
}
