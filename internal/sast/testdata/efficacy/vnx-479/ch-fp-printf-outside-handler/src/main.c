#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static volatile sig_atomic_t stop_requested;

static void on_int(int sig)
{
    (void)sig;
    stop_requested = 1;
}

int main(void)
{
    char *buf = malloc(64);
    signal(SIGINT, on_int);
    while (!stop_requested) {
        printf("working\n");
    }
    free(buf);
    exit(0);
}
