#include <signal.h>
#include <string.h>

void setup(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
~>    sigaction(SIGILL, &sa, NULL);
}
