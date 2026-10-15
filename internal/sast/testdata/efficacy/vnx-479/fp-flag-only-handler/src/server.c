#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;

static void on_term(int sig)
{
    (void)sig;
    stop_requested = 1;
    static const char msg[] = "terminating\n";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
}

static void on_abort(int sig)
{
    _exit(128 + sig);
}

int main(void)
{
    signal(SIGTERM, on_term);
    signal(SIGABRT, on_abort);
    while (!stop_requested) {
        printf("working\n");
    }
    return 0;
}
