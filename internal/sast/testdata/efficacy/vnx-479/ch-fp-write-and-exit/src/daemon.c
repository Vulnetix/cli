#include <signal.h>
#include <string.h>
#include <unistd.h>

static void on_term(int sig)
{
    static const char msg[] = "terminating\n";
    (void)sig;
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(1);
}

int main(void)
{
    signal(SIGTERM, on_term);
    return 0;
}
