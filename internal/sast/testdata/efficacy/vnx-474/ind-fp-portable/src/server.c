#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void on_hup(int sig) { (void)sig; }

void setup(char *buf, size_t n)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_hup;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    sigaction(SIGHUP, &sa, NULL);
    snprintf(buf, n, "pid=%d", (int)getpid());
    if (fork() == 0)
        _exit(0);
}
