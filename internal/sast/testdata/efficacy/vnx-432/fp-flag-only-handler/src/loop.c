#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;

static void request_stop(int sig)
{
    static const char msg[] = "stop\n";
    stop_requested = 1;
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(1);
}

int main(void)
{
    signal(SIGINT, request_stop);
    signal(SIGTERM, request_stop);
    while (!stop_requested)
        pause();
    return 0;
}
