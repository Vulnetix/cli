#include <signal.h>
#include <unistd.h>
#include <string.h>

static volatile sig_atomic_t got = 0;
static int pipefd[2];

static void on_int(int sig)
{
    (void)sig;
    got = 1;
    write(pipefd[1], "x", 1);
}

static void on_term(int sig)
{
    static const char m[] = "bye\n";
    write(2, m, strlen(m));
    _exit(1);
}

int main(void)
{
    signal(SIGINT, on_int);
    signal(SIGTERM, on_term);
    signal(SIGHUP, SIG_IGN);
    return 0;
}
