#include <signal.h>
#include <stdio.h>

static FILE *out;

static void shutdown_files(void) { fclose(out); }

static void on_shutdown(int sig)
{
    (void)sig;
    shutdown_files();
}

int main(void)
{
    struct sigaction sa;
    sa.sa_handler = on_shutdown;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
~>    sigaction(SIGINT, &sa, NULL);
~>    sigaction(SIGTERM, &sa, NULL);
    return 0;
}
