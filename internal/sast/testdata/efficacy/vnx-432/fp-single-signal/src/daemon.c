#include <signal.h>
#include <stdlib.h>

static char *global_buf;

static void on_term(int sig)
{
    free(global_buf);
    exit(0);
}

int main(void)
{
    signal(SIGTERM, on_term);
    global_buf = malloc(64);
    return 0;
}
