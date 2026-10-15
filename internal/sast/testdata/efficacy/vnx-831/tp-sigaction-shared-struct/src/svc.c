#include <signal.h>
#include <stdio.h>
#include <string.h>

static FILE *journal;

static void flush_journal(void)
{
    fflush(journal);
    fclose(journal);
}

static void on_shutdown(int signo)
{
    (void)signo;
    flush_journal();
}

void install_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_shutdown;
    sigemptyset(&sa.sa_mask);
~>    sigaction(SIGINT, &sa, NULL);
~>    sigaction(SIGTERM, &sa, NULL);
~>    sigaction(SIGUSR1,
              &sa, NULL);
}
