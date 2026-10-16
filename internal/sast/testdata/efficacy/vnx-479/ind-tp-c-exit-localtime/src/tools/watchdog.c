#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

void ill_handler(int sig)
{
    time_t now = time(NULL);
~>    struct tm *tm = localtime(&now);
    (void) tm;
~>    exit(sig);
}

int main(void)
{
    signal(SIGILL, ill_handler);
    pause();
    return 0;
}
