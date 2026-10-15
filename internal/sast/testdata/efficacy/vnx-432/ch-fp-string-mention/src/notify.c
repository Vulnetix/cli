#include <signal.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t got_signal;

static void note_signal(int sig)
{
    static const char msg[] = "signal received, will free() resources and exit() from main\n";
    got_signal = sig;
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
}

int main(void)
{
    signal(SIGINT, note_signal);
    signal(SIGTERM, note_signal);
    while (!got_signal)
        pause();
    return 0;
}
