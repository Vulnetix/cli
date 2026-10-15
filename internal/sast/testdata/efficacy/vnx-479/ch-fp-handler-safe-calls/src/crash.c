#include <signal.h>
#include <string.h>
#include <unistd.h>

static void on_segv(int sig)
{
    static const char msg[] = "fatal: segmentation fault\n";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
    signal(sig, SIG_DFL);
    raise(sig);
    _exit(128 + sig);
}

void install_crash_handler(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_segv;
    sigaction(SIGSEGV, &sa, NULL);
    printf("handler installed\n");
}
