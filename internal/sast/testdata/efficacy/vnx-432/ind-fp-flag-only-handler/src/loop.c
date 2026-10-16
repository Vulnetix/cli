#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;

static void request_stop(int sig)
{
    (void)sig;
    stop_requested = 1;
}

static void hard_exit(int sig)
{
    static const char msg[] = "aborting\n";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(128 + sig);
}

void install(void)
{
    struct sigaction sa;
    sa.sa_handler = request_stop;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGTERM, &sa, NULL);

    struct sigaction hard;
    hard.sa_handler = hard_exit;
    sigemptyset(&hard.sa_mask);
    hard.sa_flags = SA_NODEFER;
    sigaction(SIGQUIT, &hard, NULL);
}
