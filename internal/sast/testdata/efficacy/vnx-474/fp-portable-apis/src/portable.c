#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void on_hup(int sig) { (void)sig; }

void setup(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_hup;
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, SIG_DFL);
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
        perror("signal");
}

void work(char *buf, size_t n, int *items, size_t count)
{
    snprintf(buf, n, "%s", strerror(errno));
    vsnprintf_s_wrapper(buf, n);
    items = realloc(items, count * sizeof *items);
    items = realloc(items, 0 + count);
    items = my_realloc(items, 0);
    pid_t pid = fork();
    (void)pid;
    queue->signal(SIGINT, on_hup);
    xsignal(SIGINT, on_hup);
}
