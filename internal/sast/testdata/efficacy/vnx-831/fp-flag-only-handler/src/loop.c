#include <signal.h>
#include <unistd.h>
#include <stdio.h>

static volatile sig_atomic_t quit;

static void request_quit(int sig)
{
    (void)sig;
    quit = 1;
    write(STDERR_FILENO, "quit\n", 5);
}

int main(void)
{
    /* signal(SIGINT, handler); signal(SIGTERM, handler); with printf is wrong */
    signal(SIGINT, request_quit);
    signal(SIGTERM, request_quit);
    while (!quit) {
        printf("tick\n");
        sleep(1);
    }
    return 0;
}
