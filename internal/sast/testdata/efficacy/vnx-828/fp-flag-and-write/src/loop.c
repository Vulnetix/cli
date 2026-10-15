#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

static volatile sig_atomic_t stop_requested = 0;

static void on_stop(int sig)
{
    static const char msg[] = "stopping\n";
    (void)sig;
    stop_requested = 1;
    write(STDERR_FILENO, msg, sizeof msg - 1);
    if (sig == SIGQUIT) {
        _exit(2);
    }
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_stop;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    while (!stop_requested) {
        printf("working\n");
        sleep(1);
    }
    return 0;
}
