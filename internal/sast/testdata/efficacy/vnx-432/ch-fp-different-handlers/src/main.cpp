#include <csignal>
#include <cstdlib>
#include <iostream>

static void on_int(int)
{
    std::cerr << "interrupted" << std::endl;
    std::exit(130);
}

static void on_term(int)
{
    std::cerr << "terminated" << std::endl;
    std::exit(143);
}

static void on_crash(int sig)
{
    std::cerr << "fatal signal " << sig << std::endl;
    std::abort();
}

int main()
{
    std::signal(SIGINT, on_int);
    std::signal(SIGTERM, on_term);
    std::signal(SIGSEGV, on_crash);
    std::signal(SIGABRT, on_crash);
    std::signal(SIGPIPE, SIG_IGN);
    return 0;
}
