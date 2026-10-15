#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

static void log_msg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

extern "C" void handle_int(int sig)
{
~>    log_msg("interrupted by %d\n", sig);
~>    std::exit(130);
}

int main()
{
    std::signal(SIGINT, handle_int);
    return 0;
}
