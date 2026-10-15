#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static FILE *log_fp;

static void cleanup(void)
{
    fclose(log_fp);
    unlink("/run/daemon.pid");
}

static void remove_pidfile(void)
{
    unlink("/run/daemon.pid");
}

void handle_term(int signo)
{
    (void)signo;
~>    cleanup();
    remove_pidfile();
~>    fprintf(stderr,
            "terminating\n");
~>    exit(1);
}

void install(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handle_term;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
}
