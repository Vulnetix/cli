#include <execinfo.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

static const char msg[] = "fatal: segmentation fault\n";

static void on_segv(int sig)
{
    void *frames[64];
    int n = backtrace(frames, 64);

    write(STDERR_FILENO, msg, sizeof msg - 1);
    backtrace_symbols_fd(frames, n, STDERR_FILENO);
    signal(sig, SIG_DFL);
    raise(sig);
}

void install(void)
{
    signal(SIGSEGV, on_segv);
}
