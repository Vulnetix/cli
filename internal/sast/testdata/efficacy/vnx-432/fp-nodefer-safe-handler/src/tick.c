#include <signal.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t ticks;

static void on_alarm(int sig)
{
    (void)sig;
    ticks++;
    write(STDERR_FILENO, ".", 1);
}

void start_ticker(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGALRM, &sa, NULL);
    alarm(1);
}
