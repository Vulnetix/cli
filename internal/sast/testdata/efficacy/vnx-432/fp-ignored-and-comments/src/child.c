#include <signal.h>
#include <stdlib.h>

static void reap(int sig)
{
    free(NULL);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGUSR1, reap);
    /* signal(SIGUSR2, reap); kept for reference */
    // signal(SIGHUP, reap);
    const char *doc = "signal(SIGINT, reap); signal(SIGTERM, reap);";
    return 0;
}
