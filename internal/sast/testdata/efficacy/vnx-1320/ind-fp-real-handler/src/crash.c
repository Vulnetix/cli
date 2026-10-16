#include <signal.h>
#include <unistd.h>
#include <string.h>

static void on_segv(int sig) {
    static const char msg[] = "fatal fault\n";
    write(2, msg, sizeof msg - 1);
    _exit(139);
}

void install(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_segv;
    sigaction(SIGSEGV, &sa, NULL);
    signal(SIGABRT, SIG_DFL);
}
