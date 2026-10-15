#include <signal.h>
#include <sys/wait.h>

static void reap(int sig)
{
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}

void install_reaper(void)
{
~>    signal(SIGCHLD, reap);
}
