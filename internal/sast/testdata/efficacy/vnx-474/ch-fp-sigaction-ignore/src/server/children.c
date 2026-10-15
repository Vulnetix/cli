#include <signal.h>
#include <string.h>

static void reap(int sig) { (void)sig; }

void install_reaper(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = reap;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, SIG_DFL);
}
