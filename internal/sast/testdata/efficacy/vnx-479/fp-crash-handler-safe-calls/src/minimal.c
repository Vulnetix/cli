#include <execinfo.h>
#include <signal.h>
#include <unistd.h>

static void on_segv(int sig)
{
    void *frames[64];
    int n = backtrace(frames, 64);
    static const char msg[] = "segmentation fault\n";

    write(STDERR_FILENO, msg, sizeof msg - 1);
    backtrace_symbols_fd(frames, n, STDERR_FILENO);
    /* printf("never call printf here"); */
    signal(sig, SIG_DFL);
    raise(sig);
}

void install(void)
{
    signal(SIGSEGV, on_segv);
}
