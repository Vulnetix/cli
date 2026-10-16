#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t stop;

static void on_sig(int sig)
{
    stop = 1;
    write(2, "s", 1);
}

int main(void)
{
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    return 0;
}
