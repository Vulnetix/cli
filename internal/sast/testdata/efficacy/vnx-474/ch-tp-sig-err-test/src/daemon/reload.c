#include <signal.h>
#include <stdlib.h>

static volatile sig_atomic_t want_reload;

static void on_hup(int sig) { (void)sig; want_reload = 1; }

void setup(void)
{
~>    if (signal(SIGHUP, on_hup) == SIG_ERR)
        abort();
    signal(SIGHUP, on_hup);
}
