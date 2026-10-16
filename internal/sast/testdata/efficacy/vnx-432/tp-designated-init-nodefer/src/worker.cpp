#include <csignal>
#include <iostream>

static void on_usr1(int)
{
    std::cerr << "dumping statistics" << std::endl;
}

void install_stats_handler()
{
    struct sigaction sa = {
        .sa_handler = on_usr1,
~>        .sa_flags = SA_NODEFER,
    };
    sigaction(SIGUSR1, &sa, nullptr);
}
