#include <signal.h>

extern void on_hup(int sig);

void install_handlers(void)
{
    struct sigaction sa;
    sa.sa_handler = on_hup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGHUP, &sa, NULL);

    struct sigaction ign;
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    ign.sa_flags = SA_NODEFER;
    sigaction(SIGPIPE, &ign, NULL);
}
