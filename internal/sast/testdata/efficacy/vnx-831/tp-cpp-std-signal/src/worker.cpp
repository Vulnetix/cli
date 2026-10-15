#include <csignal>
#include <iostream>

void on_signal(int sig)
{
    std::cerr << "signal " << sig << " received\n";
}

int main()
{
~>    std::signal(SIGINT, on_signal);
~>    std::signal(SIGQUIT, &on_signal);
    std::signal(SIGPIPE, SIG_IGN);
    return 0;
}
