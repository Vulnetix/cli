#include <csignal>
#include <cstdio>

extern "C" void flush_logs(void)
{
    std::fflush(stdout);
}

extern "C" void on_quit(int)
{
    flush_logs();
}

int main()
{
~>    std::signal(SIGQUIT, on_quit);
~>    std::signal(SIGTERM, on_quit);
    return 0;
}
